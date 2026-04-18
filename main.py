import os
import sys
import importlib.metadata
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DB_CONFIGS, OUTPUT_CSV, MAX_SCAN_MINUTES, TABLE_TIMEOUT_SECONDS
from core.db_connector import get_connection, get_all_tables, get_primary_key_col, stream_table_rows
from core.csv_writer import CSVWriter
from core.dispatcher import dispatch
from core.task_queue import ai_stats
from core.logger import ScanLogger
from scanners.dbobject import scan_db_objects

_start_time = None
_writer_lock = threading.Lock()


def _time_left() -> float:
    return MAX_SCAN_MINUTES * 60 - (time.time() - _start_time)


def _scan_table(conn, db_type, db_name, table_name, writer, log: ScanLogger, label: str):
    pk_col = get_primary_key_col(conn, db_type, db_name, table_name)
    row_count = 0
    hit_count = 0

    deadline = time.time() + TABLE_TIMEOUT_SECONDS
    for pk_value, row in stream_table_rows(conn, db_type, table_name, pk_col):
        if time.time() > deadline:
            log.warning(label, f"表 {table_name} 超时，已跳过剩余行")
            break
        if _time_left() <= 0:
            log.warning(label, "总时间将耗尽，停止扫描")
            return row_count, hit_count

        for field_name, value in row.items():
            findings = dispatch(field_name, value, pk_value, table_name, db_type, db_name)
            if findings:
                hit_count += len(findings)
                with _writer_lock:
                    for f in findings:
                        writer.write_row(f)
        row_count += 1

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
        log.info("system", f"Python {sys.version.split()[0]} | pymysql={_pymysql_ver} | psycopg2={_psycopg2_ver}")
        log.info("system", f"开始扫描 | 输出: {OUTPUT_CSV} | 时限: {MAX_SCAN_MINUTES}min")

        tasks = [
            (db_type, db_name)
            for db_type, cfg in DB_CONFIGS.items()
            for db_name in cfg["databases"]
        ]

       with ThreadPoolExecutor(max_workers=min(4, len(tasks))) as executor::
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
                 f"AI推理 {stats['total_calls']}次 均值{stats['avg_time_s']}s/次")
        log.summary()


if __name__ == "__main__":
    main()
