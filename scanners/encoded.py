"""
编码/变形数据扫描器。

关键改动(基于 example.csv 分析):
  1. 引入 _STRONG_ENCODED_FIELD_RE:字段名含 encoded_xxx / payload / base64
     等强提示时,绕开 _is_encoded_value 启发式,无条件跑 decode_recursive。
     理由: example 里 encoded 形态全部字段名都是 encoded_rx/encoded_report/
     encoded_payload,启发式判断第一层解码不够直接可能漏。
  2. _decoded_looks_sensitive 扩展了强 pattern 列表,覆盖医保号/病历号/
     公积金号/社保号/车牌/VIN/USCC/护照等有结构先验的类型。
  3. decode_recursive 四重防御(深度/单步长度/循环自指/累计膨胀比)。
"""
import re
import base64
import urllib.parse
from core.patterns import extract_sensitive_from_value, REGEX_PATTERNS
from core.config import SENSITIVE_LEVEL_MAP


# ── 解码链防御上限 ────────────────────────────────────────────────
MAX_DECODE_DEPTH = 5          # 递归深度上限
MAX_DECODED_LEN = 200_000     # 单步解码后长度上限
MAX_CUMULATIVE_RATIO = 10     # 累计膨胀比(末值长度 / 初始长度)


# ── 字段名黑名单 / 白名单 ────────────────────────────────────────
PASSWORD_FIELD_KEYWORDS = {"password", "passwd", "pwd", "secret", "token",
                            "api_key", "apikey", "private_key", "secret_key"}

# [新] 字段名强提示 encoded 形态。命中则绕开 _is_encoded_value 启发式。
_STRONG_ENCODED_FIELD_RE = re.compile(
    r"(?:encoded[_\w]*|payload|base64|encode|cipher|ciphertext|encrypted)",
    re.IGNORECASE,
)


# ── 模块级预编译正则 ──────────────────────────────────────────────
_HAS_LETTER = re.compile(r"[a-zA-Z]")
_HAS_AF = re.compile(r"[a-fA-F]")
_HAS_CHINESE = re.compile(r"[\u4e00-\u9fa5]")
_UNICODE_ESC = re.compile(r"\\u[0-9a-fA-F]{4}")
_PERCENT_ENC = re.compile(r"%[0-9a-fA-F]{2}")
# 快速预检:base64 合法字符集(避免对非 base64 串走完整解码)
_B64_CHARS = re.compile(r"^[A-Za-z0-9+/\-_=]+$")
# 快速预检:hex 合法字符集
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
    # 快速预检:长度至少 8,必须含字母,字符全在 base64 合法集内
    if len(stripped) < 8:
        return None
    if not _HAS_LETTER.search(stripped):
        return None
    if not _B64_CHARS.match(stripped.rstrip("=")):
        return None
    # 支持 URL-safe base64
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
    """若 s 是 base64 编码的图片数据,返回原始字节;否则返回 None。"""
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
    # 快速预检
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
    """修复 unicode_escape codec 对中文字符乱码的问题。"""
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
      闸1: 深度上限 max_rounds 轮
      闸2: 单步解码后长度 > MAX_DECODED_LEN → 截停(防 zip-bomb 式膨胀)
      闸3: 循环自指(本轮解码结果已出现在 seen 里)→ 截停
      闸4: 末值 / 初值 > MAX_CUMULATIVE_RATIO → 截停
    任一闸触发都静默返回当前最后合法结果 + 已完成的 chain,不抛异常。
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
    判断解码结果是否"看起来有价值"。
    扩展:纳入所有有强先验结构的类型,避免 encoded+医保号 等被判成 structured。
      - 含中文 → 一定有价值
      - 命中强 pattern → 一定有价值
    """
    if not decoded:
        return False
    if _HAS_CHINESE.search(decoded):
        return True
    # 所有自带结构校验或特定前缀的类型都算"强特征"
    strong_patterns = (
        "PHONE_NUMBER", "EMAIL", "ID_CARD", "BANK_CARD",
        "ADDRESS", "IP_ADDRESS", "GPS_COORDINATE",
        "MEDICAL_INSURANCE_NO",   # YB + 14-16 位,前缀强
        "MEDICAL_RECORD_NO",      # MR + 9 位,前缀强
        "HOUSING_FUND_NO",        # 2 字母 + 20/21/... + 8 位,前缀强
        "SOCIAL_SECURITY_NO",     # 省份简称 + 2 字母 + 8 位,前缀强
        "LICENSE_PLATE",          # 省份汉字 + 字母数字,前缀强
        "VIN_CODE",               # 17 位特定字符集
        "USCC",                   # 18 位混合,有校验位
        "PASSPORT",               # [EGDPS] + 8 位数字
    )
    for p_name in strong_patterns:
        pat = REGEX_PATTERNS.get(p_name)
        if pat is not None and pat.search(decoded):
            return True
    return False


def _is_encoded_value(s: str) -> bool:
    if not s or not isinstance(s, str):
        return False
    stripped = s.strip()
    # 纯数字不视为编码(手机号/身份证等)
    if stripped.isdigit():
        return False

    # URL 编码 / Unicode 转义:特征明显,直接通过
    if _PERCENT_ENC.search(stripped):
        return True
    if _UNICODE_ESC.search(stripped):
        return True

    # base64:除了能解码外,还要求解码结果"看起来有价值"
    decoded_b64 = _try_base64_decode(stripped)
    if decoded_b64 is not None and _decoded_looks_sensitive(decoded_b64):
        return True

    # hex:同样要求解码后有价值
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


def _scan_decoded(decoded: str, record_id, table_name, field_col_name,
                  db_type, db_name) -> list:
    """解码后扫描:先尝试 JSON/XML,再走正则。"""
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
    """
    编码字段扫描。
    策略:
      A. 密码字段 → 跳过(由 dispatcher 层 PASSWORD_FIELD 处理)
      B. 字段名强提示为 encoded_xxx / payload / base64 等
         → 无条件 decode_recursive,不看 _is_encoded_value 启发式
         理由: example.csv 里 encoded 形态的字段名全部带 encoded_ 前缀,
         启发式判断对多层嵌套编码不稳;字段名是强信号应当直接信任。
      C. 否则走原有 _is_encoded_value 启发式判断
    """
    if not raw_value or not isinstance(raw_value, str):
        return []

    fn = field_name.lower()
    if any(kw in fn for kw in PASSWORD_FIELD_KEYWORDS):
        return []

    # [新] 字段名强提示 → 绕开 _is_encoded_value 启发式
    strong_field = bool(_STRONG_ENCODED_FIELD_RE.search(fn))

    if not strong_field:
        if not _is_encoded_value(raw_value):
            return []

    decoded, chain = decode_recursive(raw_value)
    if not chain or decoded == raw_value:
        # 解码失败。
        # - 启发式路径(非强字段):本来就不该有命中,直接返空
        # - 强字段路径:value 可能是明文 key:value(如 "BANK:xxx|PHONE:yyy"),
        #   dispatcher 的 5a 会兜底走 structured + data_form=encoded,这里返空
        #   不冲突(dispatcher 见 hits 为空会继续到 5a)
        return []

    return _scan_decoded(decoded, record_id, table_name, field_col_name, db_type, db_name)
