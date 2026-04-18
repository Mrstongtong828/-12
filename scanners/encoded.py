import re
import base64
import urllib.parse
from core.patterns import extract_sensitive_from_value
from core.config import SENSITIVE_LEVEL_MAP

PASSWORD_FIELD_KEYWORDS = {"password", "passwd", "pwd", "secret", "token",
                            "api_key", "apikey", "private_key", "secret_key"}

_HAS_LETTER = re.compile(r"[a-zA-Z]")
_HAS_AF = re.compile(r"[a-fA-F]")
_UNICODE_ESC = re.compile(r"\\u[0-9a-fA-F]{4}")
_PERCENT_ENC = re.compile(r"%[0-9a-fA-F]{2}")
# 快速预检：base64 合法字符集（fix P4，避免对非 base64 串走完整解码）
_B64_CHARS = re.compile(r"^[A-Za-z0-9+/\-_=]+$")
# 快速预检：hex 合法字符集
_HEX_CHARS = re.compile(r"^[0-9a-fA-F]+$")


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b < 0x7f or b >= 0x80)
    return printable / len(data)


def _try_url_decode(s: str):
    if not _PERCENT_ENC.search(s):
        return None
    try:
        decoded = urllib.parse.unquote(s, errors="strict")
        return decoded if decoded != s else None
    except Exception:
        return None


def _try_base64_decode(s: str):
    stripped = s.strip()
    # 快速预检：长度至少8，必须含字母，字符全在 base64 合法集内（fix P4）
    if len(stripped) < 8:
        return None
    if not _HAS_LETTER.search(stripped):
        return None
    if not _B64_CHARS.match(stripped.rstrip("=")):
        return None
    # 支持 URL-safe base64（fix FN3）
    is_urlsafe = ("-" in stripped or "_" in stripped)
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        if is_urlsafe:
            decoded_bytes = base64.urlsafe_b64decode(padded)
        else:
            decoded_bytes = base64.b64decode(padded, validate=True)
        if _printable_ratio(decoded_bytes) < 0.80:
            return None
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None


_IMAGE_MAGIC = (
    b'\xff\xd8',        # JPEG
    b'\x89PNG',         # PNG
    b'GIF8',            # GIF
    b'BM',              # BMP
    b'RIFF',            # WEBP (RIFF....WEBP)
)


def try_base64_as_image(s: str):
    """若 s 是 base64 编码的图片数据，返回原始字节；否则返回 None。"""
    stripped = s.strip()
    if len(stripped) < 100:
        return None
    if not _HAS_LETTER.search(stripped):
        return None
    if not _B64_CHARS.match(stripped.rstrip("=")):
        return None
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        is_urlsafe = ("-" in stripped or "_" in stripped)
        if is_urlsafe:
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(padded, validate=True)
        if any(raw.startswith(magic) for magic in _IMAGE_MAGIC):
            return raw
    except Exception:
        pass
    return None


def _try_hex_decode(s: str):
    stripped = s.strip()
    # 快速预检（fix P4）
    if len(stripped) < 8 or len(stripped) % 2 != 0:
        return None
    if not _HAS_AF.search(stripped):
        return None
    if not _HEX_CHARS.match(stripped):
        return None
    try:
        decoded_bytes = bytes.fromhex(stripped)
        if _printable_ratio(decoded_bytes) < 0.80:
            return None
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None


def _try_unicode_unescape(s: str):
    """修复原 unicode_escape codec 对中文字符乱码的问题（fix B2）。"""
    if not _UNICODE_ESC.search(s):
        return None
    try:
        decoded = re.sub(
            r"\\u([0-9a-fA-F]{4})",
            lambda m: chr(int(m.group(1), 16)),
            s,
        )
        return decoded if decoded != s else None
    except Exception:
        return None


def decode_recursive(value_str: str, max_rounds: int = 5):
    current = value_str
    chain = []
    for _ in range(max_rounds):
        changed = False
        for decode_fn, label in [
            (_try_url_decode, "url"),
            (_try_base64_decode, "base64"),
            (_try_hex_decode, "hex"),
            (_try_unicode_unescape, "unicode"),
        ]:
            result = decode_fn(current)
            if result and result != current:
                chain.append(label)
                current = result
                changed = True
                break
        if not changed:
            break
    return current, chain


def _is_encoded_value(s: str) -> bool:
    if not s or not isinstance(s, str):
        return False
    stripped = s.strip()
    # 纯数字不视为编码（手机号/身份证等）
    if stripped.isdigit():
        return False
    # 快速特征判定，避免完整解码（fix P4）
    if _PERCENT_ENC.search(stripped):
        return True
    if _UNICODE_ESC.search(stripped):
        return True
    # base64/hex 需要做一次完整解码验证
    if _try_base64_decode(stripped) is not None:
        return True
    if _try_hex_decode(stripped) is not None:
        return True
    return False


def _make_finding(db_type, db_name, table_name, field_col_name,
                  record_id, sensitive_type, extracted_value):
    level = SENSITIVE_LEVEL_MAP.get(sensitive_type, "L3")
    return {
        "db_type": db_type,
        "db_name": db_name,
        "table_name": table_name,
        "field_name": field_col_name,
        "record_id": record_id,
        "data_form": "encoded",
        "sensitive_type": sensitive_type,
        "sensitive_level": level,
        "extracted_value": extracted_value,
    }


def _scan_decoded(decoded: str, record_id, table_name, field_col_name, db_type, db_name) -> list:
    """解码后扫描：先尝试 JSON/XML，再走正则（fix B4）。"""
    findings = []
    seen = set()

    def _add(stype, val):
        key = (stype, val)
        if key not in seen:
            seen.add(key)
            findings.append(_make_finding(db_type, db_name, table_name, field_col_name,
                                          record_id, stype, val))

    stripped = decoded.strip()
    if stripped.startswith(("{", "[")):
        # 编码套 JSON
        try:
            import json
            from scanners.structured import scan_json_value
            sub = scan_json_value(stripped, record_id, table_name, field_col_name, db_type, db_name)
            for f in sub:
                f["data_form"] = "encoded"
                key = (f["sensitive_type"], f["extracted_value"])
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
            return findings
        except Exception:
            pass
    elif stripped.startswith("<"):
        # 编码套 XML
        try:
            from scanners.structured import scan_xml_value
            sub = scan_xml_value(stripped, record_id, table_name, field_col_name, db_type, db_name)
            for f in sub:
                f["data_form"] = "encoded"
                key = (f["sensitive_type"], f["extracted_value"])
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
            return findings
        except Exception:
            pass

    for stype, val in extract_sensitive_from_value(decoded):
        _add(stype, val)

    return findings


def scan_encoded_field(field_name, raw_value, record_id, table_name,
                        field_col_name, db_type, db_name):
    if not raw_value or not isinstance(raw_value, str):
        return []

    fn = field_name.lower()
    if any(kw in fn for kw in PASSWORD_FIELD_KEYWORDS):
        return []

    if not _is_encoded_value(raw_value):
        return []

    decoded, chain = decode_recursive(raw_value)
    if not chain or decoded == raw_value:
        return []

    return _scan_decoded(decoded, record_id, table_name, field_col_name, db_type, db_name)
