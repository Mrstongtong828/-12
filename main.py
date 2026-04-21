import os

# [OCR 稳定性] 必须在任何 numpy/cv2/paddle import 之前 pin OMP/MKL 线程数，
# 否则 PaddleOCR 在 Windows 上会抛 "could not create a primitive" 或段错误。
# 详见 scanners/blob.py 的注释。
os.environ.setdefault("FLAGS_use_mkldnn", "0")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("FLAGS_eager_delete_tensor_gb", "0")
os.environ.setdefault("FLAGS_allocator_strategy", "auto_growth")
# [比赛机 i5-10400/16GB]
# Why: 2026-04-21 第四轮 ocr_client.py 改为 2-slot 池化,每个 slot 由 _spawn 时的
# env 硬覆盖为 0.20(两个合计 ~6.4GB,给主进程+OS+Docker 留 ~9.6GB)。
# 主进程自身不直接调 paddle,此处值仅用于 ocr_client 没显式 override 时的兜底。
os.environ.setdefault("FLAGS_fraction_of_cpu_memory_to_use", "0.20")

import sys
import importlib.metadata
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import (
    DB_CONFIGS, OUTPUT_CSV, MAX_SCAN_MINUTES, TABLE_TIMEOUT_SECONDS,
    SAMPLE_THRESHOLD, SAMPLE_ROWS_PER_TABLE,
    DB_WORKERS, WRITER_BUFFER_SIZE,
    BLOB_TABLE_MAX_ROWS,
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
def _get_blob_columns(conn, db_type: str, db_name: str, table_name: str) -> list:
    """
    返回表的 BLOB/BYTEA 列名列表(空列表 = 非 BLOB 表)。
    配合 stream_table_rows(where_sql=...) 做 SQL 层 NULL/tiny 过滤,
    避免把 350s 预算烧在空 placeholder 行上。
    """
    try:
        if db_type == "mysql":
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                    "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s "
                    "  AND DATA_TYPE IN "
                    "    ('blob','tinyblob','mediumblob','longblob',"
                    "     'binary','varbinary')",
                    (db_name, table_name),
                )
                rows = cur.fetchall()
                return [
                    (r.get("COLUMN_NAME") if isinstance(r, dict) else r[0])
                    for r in rows
                ]
        elif db_type == "postgresql":
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = %s AND data_type = 'bytea'",
                    (table_name,),
                )
                rows = cur.fetchall()
                return [r[0] for r in rows]
    except Exception:
        pass
    return []


def _has_blob_column(conn, db_type: str, db_name: str, table_name: str) -> bool:
    """二选判定,只是 _get_blob_columns 的薄包装,保留给既有调用。"""
    return bool(_get_blob_columns(conn, db_type, db_name, table_name))


def _build_blob_where_sql(db_type: str, blob_cols: list, min_bytes: int = 200) -> str:
    """
    构造 BLOB 表的 WHERE 过滤:任一 BLOB 列非空且 > min_bytes。
    MySQL 和 PostgreSQL 都支持 OCTET_LENGTH,quote 规则不同:
      - MySQL 用反引号
      - PostgreSQL 用双引号
    """
    quote = "`" if db_type == "mysql" else '"'
    parts = [
        f"({quote}{c}{quote} IS NOT NULL AND OCTET_LENGTH({quote}{c}{quote}) > {min_bytes})"
        for c in blob_cols
    ]
    return " OR ".join(parts)


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

    # 有 PK：拿 MIN/MAX，按 ID 区间切三段
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
                        yield (pk_value, r_dict)
                else:
                    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                        cur.execute(sql)
                        rows = cur.fetchall()
                    for r in rows:
                        seq += 1
                        r_dict = dict(r)
                        pk_value = r_dict.get(pk_col, seq)
                        yield (pk_value, r_dict)
            except Exception as e:
                print(f"[ERROR] 分段抽样失败 {table_name}: {e}")
    except Exception as e:
        print(f"[ERROR] 抽样准备失败 {table_name}: {e}")


# ── 单表扫描 ─────────────────────────────────────────────────────
def _scan_database(db_type, db_name, writer, log):
    label = f"{db_type}/{db_name}"
    conn = get_connection(db_type, db_name)
    if conn is None:
        log.error(label, "无法建立连接,跳过")
        return

    try:
        tables = get_all_tables(conn, db_type, db_name)
        log.register_db(label, total_tables=len(tables))
        log.info(label, f"发现 {len(tables)} 张表")

        # [v3] 把含 BLOB/BYTEA 列的表挪到最后扫
        # 理由: OCR 子进程内存错误导致熔断时,排在 BLOB 表后面的普通表仍能正常扫描,
        #       保全 structured / unstructured_text / encoded 三大形态的 Recall
        non_blob_tables = []
        blob_tables = []
        for t in tables:
            if _has_blob_column(conn, db_type, db_name, t):
                blob_tables.append(t)
            else:
                non_blob_tables.append(t)

        if blob_tables:
            log.info(label, f"发现 {len(blob_tables)} 张 BLOB 表,延后扫描: {blob_tables}")

        ordered_tables = non_blob_tables + blob_tables

        for table in ordered_tables:
            if _time_left() <= 0:
                log.warning(label, "达到总时限,停止")
                break
            try:
                rows, hits = _scan_table(conn, db_type, db_name, table, writer, log, label)
                log.advance(label, table=table, rows=rows, findings=hits)
            except Exception as e:
                log.error(label, f"表 {table} 扫描异常: {e}")

        # 数据库对象(存储过程 + 视图)—— 即使 0 条也跑,保留完成度
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


def _scan_table(conn, db_type, db_name, table_name, writer, log: ScanLogger, label: str):
    import itertools

    pk_col = get_primary_key_col(conn, db_type, db_name, table_name)
    blob_cols = _get_blob_columns(conn, db_type, db_name, table_name)
    is_blob_table = bool(blob_cols)

    estimated = _estimate_row_count(conn, db_type, db_name, table_name)
    if estimated > SAMPLE_THRESHOLD:
        row_iter = _sampled_rows(conn, db_type, table_name, pk_col)
        log.info(label, f"表 {table_name} 估算 {estimated:,} 行，启用分层抽样")
    elif is_blob_table:
        # [1+2+3 第二轮] BLOB 表 SQL 层跳过 NULL/tiny blob,
        # 避免 350s 预算浪费在空占位行上(约能节省 30-50% 的调度成本)
        where_sql = _build_blob_where_sql(db_type, blob_cols, min_bytes=200)
        log.info(label,
                 f"表 {table_name} BLOB 列 {blob_cols},应用 NULL 过滤 "
                 f"(OCTET_LENGTH > 200)")
        row_iter = stream_table_rows(conn, db_type, table_name, pk_col,
                                     where_sql=where_sql)
    else:
        row_iter = stream_table_rows(conn, db_type, table_name, pk_col)

    if is_blob_table:
        log.info(label, f"表 {table_name} 含 BLOB 列，限制最多扫 {BLOB_TABLE_MAX_ROWS} 行")
        row_iter = itertools.islice(row_iter, BLOB_TABLE_MAX_ROWS)
        return _scan_blob_rows_parallel(
            row_iter, writer, log, label, table_name, db_type, db_name,
        )

    # 非 BLOB 表:串行
    row_count = 0
    hit_count = 0
    local_buffer = []
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

    _flush_buffer(writer, local_buffer)
    return row_count, hit_count


def _scan_blob_rows_parallel(row_iter, writer, log, label, table_name, db_type, db_name):
    """
    BLOB 表行级并行。

    Why: 2026-04-21 第二轮 ocr_client 为 3-slot 池化 + DB_WORKERS=4 并发,
    串行 dispatch 只能让一个 slot 忙,其它 slot 白嫖。这里开 ThreadPoolExecutor
    (OCR_POOL_SIZE) 同时派多行进 dispatch,3 个 slot 才能并行吃 OCR。
    DB cursor 非线程安全,所以行迭代仍由本线程独占,只把 dispatch() 派到 pool;
    CSV 写入继续走 _writer_lock 串行化。

    滑窗深度 = OCR_POOL_SIZE × 2,既不会让 pool 闲下来,也不会让 future 无限堆积。
    deadline / _time_left 过期后不再提交新任务,已提交的 future 等它跑完收尾
    (ocr_client 端 PER_IMAGE_TIMEOUT=25s 是最后一道保险)。
    """
    from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait as futures_wait
    from scanners.ocr_client import OCR_POOL_SIZE

    row_count = 0
    hit_count = 0
    local_buffer = []
    in_flight = set()
    window = max(2, OCR_POOL_SIZE * 2)

    def _process_row(pk_value, row):
        out = []
        for field_name, value in row.items():
            findings = dispatch(field_name, value, pk_value, table_name, db_type, db_name)
            if findings:
                out.extend(findings)
        return out

    def _collect(futs):
        nonlocal hit_count
        for f in futs:
            try:
                out = f.result()
            except Exception as e:
                log.error(label, f"表 {table_name} 行扫描异常: {e}")
                continue
            if out:
                hit_count += len(out)
                local_buffer.extend(out)
        if len(local_buffer) >= WRITER_BUFFER_SIZE:
            _flush_buffer(writer, local_buffer)

    deadline = time.time() + TABLE_TIMEOUT_SECONDS
    timed_out = False
    budget_out = False

    with ThreadPoolExecutor(max_workers=OCR_POOL_SIZE) as executor:
        try:
            for pk_value, row in row_iter:
                if time.time() > deadline:
                    timed_out = True
                    break
                if _time_left() <= 0:
                    budget_out = True
                    break

                in_flight.add(executor.submit(_process_row, pk_value, row))
                row_count += 1

                while len(in_flight) >= window:
                    done, in_flight = futures_wait(in_flight, return_when=FIRST_COMPLETED)
                    _collect(done)
        finally:
            if in_flight:
                _collect(in_flight)
                in_flight.clear()

    if timed_out:
        log.warning(label, f"表 {table_name} 超时({TABLE_TIMEOUT_SECONDS}s)，已扫 {row_count} 行")
    if budget_out:
        log.warning(label, "总时间将耗尽，停止扫描")

    _flush_buffer(writer, local_buffer)
    return row_count, hit_count


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

        # [稳定性] DB_WORKERS=1 时直接在主线程串行扫描,跳过 ThreadPoolExecutor。
        # [2026-04-21 第二轮] OCR 已放到 ocr_worker 子进程,主线程只做 SQL/正则,
        # 线程安全。DB_WORKERS=4 启用 4 库并发扫描,非 BLOB 阶段 wall-clock 砍到 ~60s,
        # BLOB 阶段由 fintech(2 张 BLOB 表) 决定约 900s。
        pool_size = min(DB_WORKERS, max(1, len(tasks)))
        if pool_size == 1:
            for db_type, db_name in tasks:
                try:
                    _scan_database(db_type, db_name, writer, log)
                except Exception as e:
                    log.error(f"{db_type}/{db_name}", f"未捕获异常: {e}")
        else:
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
