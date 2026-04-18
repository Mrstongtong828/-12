import os
import sys
import importlib.metadata
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import (
    DB_CONFIGS, OUTPUT_CSV, MAX_SCAN_MINUTES, TABLE_TIMEOUT_SECONDS,
    SAMPLE_THRESHOLD, SAMPLE_ROWS_PER_TABLE,
    DB_WORKERS, WRITER_BUFFER_SIZE,
)
from core.db_connector import (
    get_connection, get_all_tables, get_primary_key_col, stream_table_rows,
    _fix_row_mojibake,
)
from core.csv_writer import CSVWriter
from core.dispatcher import dispatch
from core.task_queue import ai_stats
from core.logger import ScanLogger
from scanners.dbobject import scan_db_objects

_start_time = None
_writer_lock = threading.Lock()


def _time_left() -> float:
    return MAX_SCAN_MINUTES * 60 - (time.time() - _start_time)


def _flush_buffer(writer: CSVWriter, buffer: list):
    """把本地 buffer 一次性写入 CSV（[#13] 减少锁争用）。"""
    if not buffer:
        return
    with _writer_lock:
        for f in buffer:
            writer.write_row(f)
    buffer.clear()


# ── 大表估算 & 抽样扫描（性能 #11）──────────────────────────────
def _estimate_row_count(conn, db_type: str, db_name: str, table_name: str) -> int:
    """
    估算表行数：
      - MySQL: information_schema.TABLES.TABLE_ROWS（InnoDB 下是估算值，不精确但够用）
      - PostgreSQL: pg_class.reltuples（估算值）
    估算失败返回 0（走默认全扫路径）。
    """
    try:
        if db_type == "mysql":
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT TABLE_ROWS FROM information_schema.TABLES "
                    "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s",
                    (db_name, table_name),
                )
                row = cur.fetchone()
                if row:
                    val = row.get("TABLE_ROWS") if isinstance(row, dict) else row[0]
                    return int(val or 0)
        elif db_type == "postgresql":
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT reltuples::bigint FROM pg_class "
                    "WHERE relname = %s AND relkind = 'r'",
                    (table_name,),
                )
                row = cur.fetchone()
                if row:
                    return int(row[0] or 0)
    except Exception:
        pass
    return 0


def _sampled_rows(conn, db_type: str, table_name: str, pk_col):
    """
    大表分层抽样：头/中/尾 三段，各取 SAMPLE_ROWS_PER_TABLE // 3 行。
    要求有数字型 PK；没有 PK 时降级为 LIMIT 前 SAMPLE_ROWS_PER_TABLE 行。
    用 yield (pk_value, row_dict) 保持与 stream_table_rows 兼容。
    """
    import psycopg2.extras
    per_segment = max(1, SAMPLE_ROWS_PER_TABLE // 3)

    # 无整型 PK 降级为 LIMIT
    if not pk_col:
        try:
            if db_type == "mysql":
                with conn.cursor() as cur:
                    cur.execute(f"SELECT * FROM `{table_name}` LIMIT {SAMPLE_ROWS_PER_TABLE}")
                    rows = cur.fetchall()
                for i, r in enumerate(rows, 1):
                    yield (i, _fix_row_mojibake(dict(r)))
            else:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(f'SELECT * FROM "{table_name}" LIMIT {SAMPLE_ROWS_PER_TABLE}')
                    rows = cur.fetchall()
                for i, r in enumerate(rows, 1):
                    yield (i, dict(r))
        except Exception as e:
            print(f"[ERROR] 无 PK 抽样失败 {table_name}: {e}")
        return

    # 有 PK：拿 MIN/MAX，按 ID 区间切三段，并避免重复行
    try:
        quote = "`" if db_type == "mysql" else '"'
        tbl = f"{quote}{table_name}{quote}"
        pk = f"{quote}{pk_col}{quote}"

        with conn.cursor() as cur:
            cur.execute(f"SELECT MIN({pk}), MAX({pk}) FROM {tbl}")
            row = cur.fetchone()
        if not row:
            return
        if isinstance(row, dict):
            vals = list(row.values())
            pk_min, pk_max = vals[0], vals[1]
        else:
            pk_min, pk_max = row[0], row[1]
        if pk_min is None or pk_max is None or pk_min == pk_max:
            return

        span = pk_max - pk_min
        third = span // 3
        mid_lo = pk_min + third
        mid_hi = pk_min + 2 * third

        segments = [
            f"{pk} >= {pk_min} ORDER BY {pk} ASC",
            f"{pk} >= {mid_lo} AND {pk} < {mid_hi} ORDER BY {pk} ASC",
            f"{pk} >= {mid_hi} ORDER BY {pk} DESC",
        ]

        seq = 0
        collected_pks = set()  # [dedup-fix] 跟踪已收集的主键，避免重复
        for where_order in segments:
            sql = f"SELECT * FROM {tbl} WHERE {where_order} LIMIT {per_segment}"
            try:
                if db_type == "mysql":
                    with conn.cursor() as cur:
                        cur.execute(sql)
                        rows = cur.fetchall()
                    for r in rows:
                        seq += 1
                        r_dict = _fix_row_mojibake(dict(r))
                        pk_value = r_dict.get(pk_col, seq)
                        # [dedup-fix] 有真实主键时检查重复
                        if pk_col and pk_value in collected_pks:
                            continue
                        collected_pks.add(pk_value)
                        yield (pk_value, r_dict)
                else:
                    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                        cur.execute(sql)
                        rows = cur.fetchall()
                    for r in rows:
                        seq += 1
                        r_dict = dict(r)
                        pk_value = r_dict.get(pk_col, seq)
                        # [dedup-fix] 有真实主键时检查重复
                        if pk_col and pk_value in collected_pks:
                            continue
                        collected_pks.add(pk_value)
                        yield (pk_value, r_dict)
            except Exception as e:
                print(f"[ERROR] 分段抽样失败 {table_name}: {e}")
    except Exception as e:
        print(f"[ERROR] 抽样准备失败 {table_name}: {e}")


# ── 单表扫描 ─────────────────────────────────────────────────────
def _scan_table(conn, db_type, db_name, table_name, writer, log: ScanLogger, label: str):
    pk_col = get_primary_key_col(conn, db_type, db_name, table_name)
    row_count = 0
    hit_count = 0

    # [#13] 本地 buffer，减少锁争用
    local_buffer = []

    # [#11] 估算行数，决定走全扫还是抽样
    estimated = _estimate_row_count(conn, db_type, db_name, table_name)
    if estimated > SAMPLE_THRESHOLD:
        row_iter = _sampled_rows(conn, db_type, table_name, pk_col)
        log.info(label, f"表 {table_name} 估算 {estimated:,} 行，启用分层抽样")
    else:
        row_iter = stream_table_rows(conn, db_type, table_name, pk_col)

    deadline = time.time() + TABLE_TIMEOUT_SECONDS
    for pk_value, row in row_iter:
        if time.time() > deadline:
            log.warning(label, f"表 {table_name} 超时({TABLE_TIMEOUT_SECONDS}s)，已扫 {row_count} 行")
            break
        if _time_left() <= 0:
            log.warning(label, "总时间将耗尽，停止扫描")
            _flush_buffer(writer, local_buffer)
            return row_count, hit_count

        for field_name, value in row.items():
            findings = dispatch(field_name, value, pk_value, table_name, db_type, db_name)
            if findings:
                hit_count += len(findings)
                local_buffer.extend(findings)
                if len(local_buffer) >= WRITER_BUFFER_SIZE:
                    _flush_buffer(writer, local_buffer)
        row_count += 1

    # 表扫完后把 buffer 刷一次
    _flush_buffer(writer, local_buffer)
    return row_count, hit_count


def _scan_database(db_type, db_name, writer, log: ScanLogger):
    label = f"{db_type}/{db_name}"
    conn = get_connection(db_type, db_name)
    if conn is None:
        log.error(label, "无法建立连接，跳过")
        return

    try:
        tables = get_all_tables(conn, db_type, db_name)
        log.register_db(label, total_tables=len(tables))
        log.info(label, f"发现 {len(tables)} 张表")

        for table in tables:
            if _time_left() <= 0:
                log.warning(label, "达到总时限，停止")
                break
            try:
                rows, hits = _scan_table(conn, db_type, db_name, table, writer, log, label)
                log.advance(label, table=table, rows=rows, findings=hits)
            except Exception as e:
                log.error(label, f"表 {table} 扫描异常: {e}")

        # 数据库对象（存储过程 + 视图）
        try:
            db_obj_findings = scan_db_objects(conn, db_type, db_name)
            if db_obj_findings:
                with _writer_lock:
                    for f in db_obj_findings:
                        writer.write_row(f)
                log.info(label, f"db_object 发现 {len(db_obj_findings)} 条")
        except Exception as e:
            log.error(label, f"db_object 扫描异常: {e}")

    finally:
        conn.close()


def main():
    global _start_time
    os.makedirs("output", exist_ok=True)
    _start_time = time.time()

    db_labels = [
        f"{db_type}/{db_name}"
        for db_type, cfg in DB_CONFIGS.items()
        for db_name in cfg["databases"]
    ]

    with ScanLogger(db_labels) as log, CSVWriter(OUTPUT_CSV) as writer:
        try:
            _pymysql_ver = importlib.metadata.version('pymysql')
        except importlib.metadata.PackageNotFoundError:
            _pymysql_ver = '?'
        try:
            _psycopg2_ver = importlib.metadata.version('psycopg2-binary')
        except importlib.metadata.PackageNotFoundError:
            _psycopg2_ver = '?'
        log.info("system",
                 f"Python {sys.version.split()[0]} | pymysql={_pymysql_ver} | psycopg2={_psycopg2_ver}")
        log.info("system",
                 f"开始扫描 | 输出: {OUTPUT_CSV} | 总时限: {MAX_SCAN_MINUTES}min | "
                 f"单表: {TABLE_TIMEOUT_SECONDS}s | DB 并发: {DB_WORKERS}")

        tasks = [
            (db_type, db_name)
            for db_type, cfg in DB_CONFIGS.items()
            for db_name in cfg["databases"]
        ]

        # [bug 修复 + #14] 修掉原来 `as executor::` 的语法错误；
        # 并发度从 min(4, len(tasks)) 放大到 DB_WORKERS（默认 8）
        # —— 当 OCR 串行时，空闲线程可以继续扫其他非 OCR 表
        pool_size = min(DB_WORKERS, max(1, len(tasks)))
        with ThreadPoolExecutor(max_workers=pool_size) as executor:
            futures = {
                executor.submit(_scan_database, db_type, db_name, writer, log): (db_type, db_name)
                for db_type, db_name in tasks
            }
            for future in as_completed(futures):
                db_type, db_name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    log.error(f"{db_type}/{db_name}", f"未捕获异常: {e}")

        elapsed = time.time() - _start_time
        stats = ai_stats()
        log.info("system",
                 f"完成 耗时={elapsed:.1f}s | "
                 f"AI推理 {stats['total_calls']}次 | "
                 f"均值 {stats['avg_time_s']}s/次 | "
                 f"平均等待 {stats['avg_wait_s']}s/次")
        log.summary()


if __name__ == "__main__":
    main()
