import re
import base64
import urllib.parse
from core.patterns import extract_sensitive_from_value, REGEX_PATTERNS
from core.config import SENSITIVE_LEVEL_MAP

MAX_DECODE_DEPTH = 5          # 递归深度上限
MAX_DECODED_LEN = 200_000     # 单步解码后长度上限
MAX_CUMULATIVE_RATIO = 10     # 累计膨胀比(末值长度 / 初始长度)


PASSWORD_FIELD_KEYWORDS = {"password", "passwd", "pwd", "secret", "token",
                            "api_key", "apikey", "private_key", "secret_key"}

# ── 模块级预编译正则 ──────────────────────────────────────────────
_HAS_LETTER = re.compile(r"[a-zA-Z]")
_HAS_AF = re.compile(r"[a-fA-F]")
_HAS_CHINESE = re.compile(r"[\u4e00-\u9fa5]")
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

def decode_recursive(value_str: str, max_rounds: int = MAX_DECODE_DEPTH):
    """
    递归解码链,带四重防御:
      1. 深度上限: max_rounds 轮
      2. 单步长度上限: 解码后 > MAX_DECODED_LEN → 截停
      3. 循环自指检测: 中间串已见过 → 截停
      4. 累计膨胀比上限: 末值/初值 > MAX_CUMULATIVE_RATIO → 截停
    任何一闸触发都静默停止,返回当前最后合法结果 + 已完成的 chain。
    """
    current = value_str
    chain = []
    seen = {current}
    initial_len = max(1, len(value_str))

    for _ in range(max_rounds):
        changed = False
        for decode_fn, label in [
            (_try_url_decode, "url"),
            (_try_base64_decode, "base64"),
            (_try_hex_decode, "hex"),
            (_try_unicode_unescape, "unicode"),
        ]:
            result = decode_fn(current)
            if result is None or result == current:
                continue

            # 闸 2: 单步长度
            if len(result) > MAX_DECODED_LEN:
                return current, chain
            # 闸 3: 循环自指
            if result in seen:
                return current, chain
            # 闸 4: 累计膨胀比
            if len(result) / initial_len > MAX_CUMULATIVE_RATIO:
                return current, chain

            chain.append(label)
            current = result
            seen.add(current)
            changed = True
            break

        if not changed:
            break

    return current, chain

def _decoded_looks_sensitive(decoded: str) -> bool:
    """
    [fix #9] 判断解码结果是否"看起来有价值"：
      - 含中文 → 一定是真编码（敏感数据通常含中文）
      - 含手机号/邮箱/身份证等强特征 → 很可能是真编码

    这样可以避免把正常的英文长串（UUID、哈希、token 本身）
    误判为"已编码"然后产生不可预测的 FP。
    """
    if not decoded:
        return False
    if _HAS_CHINESE.search(decoded):
        return True
    # 至少命中一个强模式才认为是真编码
    strong_patterns = ("PHONE_NUMBER", "EMAIL", "ID_CARD", "BANK_CARD",
                       "ADDRESS", "IP_ADDRESS", "GPS_COORDINATE")
    for p_name in strong_patterns:
        if REGEX_PATTERNS[p_name].search(decoded):
            return True
    return False


def _is_encoded_value(s: str) -> bool:
    if not s or not isinstance(s, str):
        return False
    stripped = s.strip()
    # 纯数字不视为编码（手机号/身份证等）
    if stripped.isdigit():
        return False

    # URL 编码 / Unicode 转义：特征明显，直接通过
    if _PERCENT_ENC.search(stripped):
        return True
    if _UNICODE_ESC.search(stripped):
        return True

    # [fix #9] base64：除了能解码外，还要求解码结果"看起来有价值"
    decoded_b64 = _try_base64_decode(stripped)
    if decoded_b64 is not None and _decoded_looks_sensitive(decoded_b64):
        return True

    # [fix #9] hex：同样要求解码后有价值
    decoded_hex = _try_hex_decode(stripped)
    if decoded_hex is not None and _decoded_looks_sensitive(decoded_hex):
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
