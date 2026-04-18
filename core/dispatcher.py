"""
字段值分发器：嗅探数据特征，路由到正确的扫描器。

优先级链：
  binary → blob
  password字段名 → structured (PASSWORD_OR_SECRET)
  {/[ 开头 → semi_structured (JSON)
  < 开头 → semi_structured (XML)
  编码特征 → encoded (递归解码链)
  长自然语言文本 → unstructured_text
  其余 → structured
"""
import re

from scanners.structured import (
    scan_structured_field,
    scan_json_value,
    scan_xml_value,
)
from scanners.encoded import (
    scan_encoded_field,
    _is_encoded_value,
    try_base64_as_image,
)
from scanners.unstructured import scan_unstructured_field, is_unstructured_text
from scanners.blob import scan_blob_field

_HEX_CHARS_DISPATCH = re.compile(r'^[0-9a-fA-F]+$')

_PWD_FIELD_RE = re.compile(
    r"\b(?:password|passwd|pass|pwd|secret|token|api_key|apikey|"
    r"access_key|secret_key|private_key|auth_token|refresh_token|"
    r"access_token|credential|pin)\b",
    re.IGNORECASE,
)


def _is_binary(value) -> bool:
    return isinstance(value, (bytes, bytearray, memoryview))


def _is_json_like(s: str) -> bool:
    stripped = s.lstrip()
    return stripped.startswith(("{", "["))


def _is_xml_like(s: str) -> bool:
    return s.lstrip().startswith("<")


def dispatch(field_name: str, value, record_id, table_name: str,
             db_type: str, db_name: str) -> list:
    """
    统一分发入口。根据值特征路由到对应扫描器，返回 findings 列表。
    每个 finding 是含完整 9 列字段的字典。
    """
    # ── 1. 二进制数据 → OCR ──────────────────────────────────────
    if _is_binary(value):
        return scan_blob_field(value, record_id, table_name, field_name, db_type, db_name)

    if value is None:
        return []

    value_str = str(value).strip()
    if not value_str:
        return []

    # ── 1b. \x 前缀十六进制字符串 → 视为 BLOB ────────────────────────
    # [B5] 要求偶数长度，避免 bytes.fromhex 因奇数长度静默失败
    if (value_str.startswith(r'\x')
            and len(value_str) > 4 and (len(value_str) - 2) % 2 == 0
            and _HEX_CHARS_DISPATCH.match(value_str[2:])):
        return scan_blob_field(value_str, record_id, table_name, field_name, db_type, db_name)

    # ── 1c. Base64 编码图片 → OCR ─────────────────────────────────────
    # [P1] 仅对无空格的长字符串尝试 base64 图片检测，减少热路径开销
    if 100 <= len(value_str) <= 10_000_000 and ' ' not in value_str and '\n' not in value_str:
        img_bytes = try_base64_as_image(value_str)
        if img_bytes is not None:
            return scan_blob_field(img_bytes, record_id, table_name, field_name, db_type, db_name)

    # ── 2. 密码/密钥字段名 → structured（整值即为敏感值）────────
    is_pwd_field = bool(_PWD_FIELD_RE.search(field_name))
    if is_pwd_field:
        return scan_structured_field(field_name, value_str, record_id,
                                     table_name, field_name, db_type, db_name)

    # ── 3. JSON → semi_structured（直接调用 JSON 扫描器）──────────
    if _is_json_like(value_str):
        hits = scan_json_value(value_str, record_id, table_name,
                               field_name, db_type, db_name)
        if hits:
            return hits
        # JSON 解析失败时，降级走结构化兜底（保持 data_form 正确由下游处理）
        return scan_structured_field(field_name, value_str, record_id,
                                     table_name, field_name, db_type, db_name)

    # ── 4. XML → semi_structured（直接调用 XML 扫描器）────────────
    if _is_xml_like(value_str):
        hits = scan_xml_value(value_str, record_id, table_name,
                              field_name, db_type, db_name)
        if hits:
            return hits
        # XML 解析失败时，降级走结构化兜底
        return scan_structured_field(field_name, value_str, record_id,
                                     table_name, field_name, db_type, db_name)

    # ── 5. 编码字段 → encoded（递归解码链）──────────────────────
    #     排除：密码字段（已在步骤2处理）、纯数字串
    if _is_encoded_value(value_str):
        hits = scan_encoded_field(field_name, value_str, record_id,
                                   table_name, field_name, db_type, db_name)
        if hits:
            return hits
        # 解码成功但无敏感命中，继续走结构化兜底

    # ── 6. 长自然语言文本 → unstructured_text ───────────────────
    if is_unstructured_text(value_str):
        return scan_unstructured_field(field_name, value_str, record_id,
                                        table_name, field_name, db_type, db_name)

    # ── 7. 默认 → structured ─────────────────────────────────────
    return scan_structured_field(field_name, value_str, record_id,
                                  table_name, field_name, db_type, db_name)
