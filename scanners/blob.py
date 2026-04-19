"""
BLOB/图片扫描器。

与旧版区别:
  旧版 : 本进程直接跑 PaddleOCR(Windows + CPU 段错误会杀进程)
  新版 : 把 OCR 外包给子进程(scanners.ocr_worker),本地只负责字节输入
         和识别结果的敏感正则匹配。子进程即使崩了也杀不死主流程。

保留:
  - OCR_CORRECTION_MAP(O→0 / I→1 等数字类易混字符纠错)
  - 对 bytes / memoryview / psycopg2 的 \\x 前缀十六进制串的兼容
  - 扫描结果的 data_form = "binary_blob"

对外 API 不变:
  scan_blob_field(blob_bytes, record_id, table_name,
                   field_col_name, db_type, db_name) -> list[finding]
"""
import re

from core.patterns import extract_sensitive_from_value
from core.config import SENSITIVE_LEVEL_MAP
from scanners.ocr_client import get_ocr_text, ocr_disabled


OCR_CORRECTION_MAP = {
    'O': '0', 'o': '0',
    'I': '1', 'l': '1',
    'S': '5',
    'B': '8',
    'Z': '2',
    'G': '6',
    'T': '7',
}

_DIGIT_LIKE = re.compile(r"[0-9OoIlSBZGT]{6,}")


def correct_ocr_text(text: str) -> str:
    """只在形似数字串的片段上替换,纯英文单词不受影响。"""
    def _correct_segment(m):
        seg = m.group()
        return "".join(OCR_CORRECTION_MAP.get(c, c) for c in seg)
    return _DIGIT_LIKE.sub(_correct_segment, text)


def _make_finding(db_type, db_name, table_name, field_col_name,
                  record_id, sensitive_type, extracted_value):
    level = SENSITIVE_LEVEL_MAP.get(sensitive_type, "L3")
    return {
        "db_type": db_type,
        "db_name": db_name,
        "table_name": table_name,
        "field_name": field_col_name,
        "record_id": record_id,
        "data_form": "binary_blob",
        "sensitive_type": sensitive_type,
        "sensitive_level": level,
        "extracted_value": extracted_value,
    }


def _normalize_to_bytes(blob):
    """把入参统一成 bytes;无法识别返 None。"""
    if blob is None:
        return None
    if isinstance(blob, memoryview):
        return bytes(blob)
    if isinstance(blob, bytearray):
        return bytes(blob)
    if isinstance(blob, bytes):
        return blob
    # psycopg2 某些版本把 BYTEA 返回成 "\\x..." 十六进制字符串
    if isinstance(blob, str):
        s = blob.strip()
        if s.startswith(r'\x') and len(s) > 4 and (len(s) - 2) % 2 == 0:
            try:
                return bytes.fromhex(s[2:])
            except ValueError:
                return None
        return None
    return None


def scan_blob_field(blob_bytes, record_id, table_name, field_col_name,
                     db_type, db_name):
    """
    BLOB 字段扫描入口。

    流程:
      1. 规范化成 bytes
      2. 若 OCR 已熔断,直接返空(不阻塞整表扫描)
      3. 调子进程拿 OCR 文本;失败/超时返空
      4. 原文 + 纠错文本取并集后跑敏感正则,去重返回
    """
    data = _normalize_to_bytes(blob_bytes)
    if not data:
        return []

    if ocr_disabled():
        return []

    raw_text = get_ocr_text(data)
    if not raw_text:
        return []

    corrected = correct_ocr_text(raw_text)

    findings = []
    seen = set()
    for scan_text in (raw_text, corrected):
        if not scan_text:
            continue
        for stype, val in extract_sensitive_from_value(scan_text):
            key = (stype, val)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_make_finding(
                db_type, db_name, table_name, field_col_name,
                record_id, stype, val,
            ))
    return findings
