"""
单条 BLOB 字段 OCR 调试工具。
用途:给定 (db_type, db_name, table, field, record_id),打印:
  1. BLOB 字节大小 / 文件类型嗅探
  2. PaddleOCR 原始输出
  3. _preprocess_ocr_text 预处理后文本
  4. _scan_digit_windows 数字窗口扫描命中
  5. extract_sensitive_from_value 最终命中
  6. 期望答案(手动传入)对比

运行:
  python scripts/debug_blob_ocr.py mysql fintech_db kyc_verification doc_image 413 \
      --expect "ID_CARD=650106196212161052" \
      --expect "BANK_CARD=622848933712390169" \
      --pk record_id

  不给 --pk 默认用 'id'; 表不同字段名也可能不同(看源码 SHOW CREATE TABLE)
"""
import sys
import os
import argparse

# 让脚本在 scripts/ 下也能 import 项目模块
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from core.db_connector import get_connection
from scanners.blob import (
    _normalize_to_bytes, _sniff_file_type, _unwrap_encoded_blob,
    _preprocess_ocr_text, _scan_digit_windows,
    correct_ocr_text, _name_char_retry_text,
)
from scanners.ocr_client import get_ocr_text, ocr_disabled
from core.patterns import extract_sensitive_from_value


def fetch_blob(db_type, db_name, table, field, record_id, pk):
    conn = get_connection(db_type, db_name)
    if conn is None:
        print(f"[ERROR] 连接 {db_type}/{db_name} 失败")
        sys.exit(1)

    sql = f"SELECT {field} FROM {table} WHERE {pk} = %s"
    print(f"[SQL] {sql}  params=({record_id},)")
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (record_id,))
            row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        print(f"[ERROR] 没查到 {pk}={record_id} 的记录")
        sys.exit(1)

    if isinstance(row, dict):
        blob = row[field]
    else:
        blob = row[0]
    return blob


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db_type", choices=["mysql", "postgresql"])
    ap.add_argument("db_name")
    ap.add_argument("table")
    ap.add_argument("field")
    ap.add_argument("record_id", type=int)
    ap.add_argument("--pk", default="id", help="主键列名,默认 id")
    ap.add_argument("--expect", action="append", default=[],
                    help="期望值,格式 TYPE=VALUE,可多次传")
    args = ap.parse_args()

    print("=" * 70)
    print(f"目标: {args.db_type}/{args.db_name}.{args.table}.{args.field}  id={args.record_id}")
    print("=" * 70)

    blob = fetch_blob(args.db_type, args.db_name, args.table, args.field,
                      args.record_id, args.pk)
    data = _normalize_to_bytes(blob)
    if not data:
        print(f"[ERROR] BLOB 规范化为 bytes 失败,原始类型={type(blob)}")
        sys.exit(1)

    # 套娃解码尝试
    ftype = _sniff_file_type(data)
    if ftype == "unknown":
        unwrapped = _unwrap_encoded_blob(data)
        if unwrapped is not data:
            print(f"[INFO] 识别到套娃编码,已解码 {len(data)} -> {len(unwrapped)} bytes")
            data = unwrapped
            ftype = _sniff_file_type(data)

    print(f"\n[1] BLOB 字节数: {len(data)}  文件类型: {ftype}")
    print(f"    前 16 字节 hex: {data[:16].hex()}")

    if ocr_disabled():
        print("\n[ERROR] OCR 已禁用 (ocr_disabled() = True)")
        sys.exit(1)

    print("\n[2] 调用 PaddleOCR...")
    raw_text = get_ocr_text(data)
    if not raw_text:
        print("    [WARN] OCR 返回空文本 —— 图片可能损坏 / 模型问题 / 太小")
    else:
        print(f"    OCR 原始输出 ({len(raw_text)} 字符):")
        print("    " + "─" * 60)
        for ln in raw_text.split("\n"):
            print(f"    │ {ln}")
        print("    " + "─" * 60)

    if raw_text:
        processed = _preprocess_ocr_text(raw_text)
        if processed != raw_text:
            print(f"\n[3] 预处理后文本 ({len(processed)} 字符):")
            print("    " + "─" * 60)
            for ln in processed.split("\n"):
                print(f"    │ {ln}")
            print("    " + "─" * 60)
        else:
            print("\n[3] 预处理无变化")

        digit_corrected = correct_ocr_text(processed)
        if digit_corrected != processed:
            print(f"\n[4] 数字纠错后文本 (片段):")
            # 只打印纠错前后不同的部分附近
            print(f"    {digit_corrected[:500]}")

        name_corrected = _name_char_retry_text(processed)
        if name_corrected != processed:
            print(f"\n[5] 姓名字形纠错后:")
            print(f"    {name_corrected[:500]}")

        print("\n[6] 数字窗口扫描命中:")
        for stype, val in _scan_digit_windows(processed):
            print(f"    {stype:25} = {val}")

        print("\n[7] 最终正则扫描命中 (主路径):")
        hits = extract_sensitive_from_value(processed)
        for stype, val in hits:
            print(f"    {stype:25} = {val}")

        if args.expect:
            print("\n[8] 期望值对比:")
            hit_set = {(s, v) for s, v in hits}
            digit_hits = {(s, v) for s, v in _scan_digit_windows(processed)}
            all_hits = hit_set | digit_hits
            for exp in args.expect:
                stype, _, val = exp.partition("=")
                stype = stype.strip()
                val = val.strip()
                in_hits = (stype, val) in all_hits
                in_text = val in processed
                status = "✅ 命中" if in_hits else (
                    "⚠️ 文本里有但正则没抓到" if in_text else
                    "❌ OCR 根本没输出这个值"
                )
                print(f"    {status}  {stype} = {val}")


if __name__ == "__main__":
    main()
