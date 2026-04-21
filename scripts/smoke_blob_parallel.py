"""
2-slot OCR pool 并行冒烟测试。

用途:
  在切回全量扫描之前,验证 ocr_client 2-slot 池 + main._scan_blob_rows_parallel
  确实并行起来了(吞吐 > 单 slot),且内存不炸。

固定参数:
  数据库:mysql/fintech_db
  表    :kyc_verification (BANK_CARD/ID_CARD 密度高,FN 里 8+3 条)
  行数  :60 (单 slot 约 90-120s,双 slot 预期 45-60s)

运行:
  venv311/Scripts/python.exe scripts/smoke_blob_parallel.py

输出解读:
  - elapsed < 70s  → 并行生效,2-slot 吞吐达标,可以跑全量
  - elapsed 接近 90s+ → 2-slot 没发挥作用(pool 没正确派发),需要排查
  - OOM / paddle 崩 → 降回 0.15 或回退到单 slot
"""
import os
import sys
import time
import itertools

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# 与 main.py 保持一致的 Paddle env(必须在 import 任何 paddle 相关模块前)
os.environ.setdefault("FLAGS_use_mkldnn", "0")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("FLAGS_eager_delete_tensor_gb", "0")
os.environ.setdefault("FLAGS_allocator_strategy", "auto_growth")
os.environ.setdefault("FLAGS_fraction_of_cpu_memory_to_use", "0.2")

from core.db_connector import get_connection, get_primary_key_col, stream_table_rows
from core.csv_writer import CSVWriter
from core.logger import ScanLogger
from scanners.ocr_client import OCR_POOL_SIZE, shutdown_ocr

import main as _main


DB_TYPE = "mysql"
DB_NAME = "fintech_db"
TABLE = "kyc_verification"
ROWS = 60
OUT_CSV = "output/smoke_parallel.csv"


def _fmt_hits(hit_types):
    from collections import Counter
    c = Counter(hit_types)
    return ", ".join(f"{k}:{v}" for k, v in c.most_common())


def main():
    print(f"[SMOKE] OCR_POOL_SIZE = {OCR_POOL_SIZE}")
    print(f"[SMOKE] 目标: {DB_TYPE}/{DB_NAME}.{TABLE}  行数 = {ROWS}")

    conn = get_connection(DB_TYPE, DB_NAME)
    if conn is None:
        print(f"[FAIL] 无法连接 {DB_TYPE}/{DB_NAME}")
        sys.exit(1)

    label = f"{DB_TYPE}/{DB_NAME}"
    pk_col = get_primary_key_col(conn, DB_TYPE, DB_NAME, TABLE)
    print(f"[SMOKE] pk_col = {pk_col}")

    row_iter = stream_table_rows(conn, DB_TYPE, TABLE, pk_col)
    row_iter = itertools.islice(row_iter, ROWS)

    # main._time_left 依赖全局 _start_time
    _main._start_time = time.time()

    hit_types = []

    class _SinkWriter:
        """包一层,嗅探 findings 而不污染 upload.csv。"""
        def __init__(self, inner):
            self._inner = inner

        def write_row(self, f):
            hit_types.append(f["sensitive_type"])
            self._inner.write_row(f)

    with ScanLogger([label]) as log, CSVWriter(OUT_CSV) as writer:
        log.register_db(label, total_tables=1)
        sink = _SinkWriter(writer)

        t0 = time.time()
        row_count, hit_count = _main._scan_blob_rows_parallel(
            row_iter, sink, log, label, TABLE, DB_TYPE, DB_NAME,
        )
        elapsed = time.time() - t0

    conn.close()
    shutdown_ocr()

    print()
    print("=" * 60)
    print(f"[RESULT] rows scanned = {row_count}")
    print(f"[RESULT] findings     = {hit_count}")
    print(f"[RESULT] elapsed      = {elapsed:.1f}s")
    if row_count > 0:
        print(f"[RESULT] per-row avg  = {elapsed/row_count:.2f}s")
        # 参考:单 slot 稳态 ~1.5-2s/行;2 slot 并行理想 ~0.8-1.0s/行
        if elapsed / row_count < 1.2:
            print("[VERDICT] ✅ 并行生效(<1.2s/行)")
        elif elapsed / row_count < 1.6:
            print("[VERDICT] ⚠️ 部分并行(1.2-1.6s/行),可接受")
        else:
            print("[VERDICT] ❌ 接近单 slot 表现,pool 派发可能有问题")
    print(f"[RESULT] hit breakdown: {_fmt_hits(hit_types)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
