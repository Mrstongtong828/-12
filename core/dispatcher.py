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

# [README 对齐] 官方规则明确:噪声行的字段值为 "N/A_数字" 形式，直接跳过。
# 在入口处快速过滤，省掉整条 dispatch 链(尤其能避免走 unstructured/blob 浪费预算)。
_NOISE_VALUE_RE = re.compile(r"^N/A_\d+$")

_HEX_CHARS_DISPATCH = re.compile(r'^[0-9a-fA-F]+$')

_PWD_FIELD_RE = re.compile(
    r"\b(?:password|passwd|pass|pwd|secret|token|api_key|apikey|"
    r"access_key|secret_key|private_key|auth_token|refresh_token|"
    r"access_token|credential|pin)\b",
    re.IGNORECASE,
)

# [Fix #4] 字段名暗示 data_form=encoded：即使 value 不是真编码（如
# "BANK_CARD:xxx|PHONE_NUMBER:yyy" 这类明文 key:value），答案也归为 encoded。
_ENCODED_FIELD_RE = re.compile(
    r"\b(?:encoded[_\w]*|payload|base64|encode|cipher|ciphertext|encrypted)\b",
    re.IGNORECASE,
)

# [Fix #2] JSON/XML 解析失败后重判自然语言用：不再要求首字符非 `[{<`。
# 长文本 + 含中文 或含自然语言标点 → 视作非结构化。
_HAS_CHINESE_DISPATCH = re.compile(r"[\u4e00-\u9fa5]")
_HAS_NATURAL_DISPATCH = re.compile(r"[\s,。！？、；：\u201c\u201d\u2018\u2019（）【】]")


def _looks_unstructured_after_parse_fail(s: str) -> bool:
    if not s or len(s) <= 10:
        return False
    return bool(_HAS_CHINESE_DISPATCH.search(s)) or bool(_HAS_NATURAL_DISPATCH.search(s))


# [Fix #3] 字段名强烈提示为"单实体结构化字段"时，跳过 is_unstructured_text
# 判定直接走 structured。修 shipping_address.full_address 被 is_unstructured_text
# 误判成 unstructured_text 导致 form-mismatch 双扣分的问题。
_STRUCTURED_FIELD_RE = re.compile(
    r"\b(?:"
    r"full_address|home_address|residence|addr|address|dizhi|"
    r"real_name|true_name|customer_name|user_name|full_name|person_name|"
    r"client_name|owner_name|contact_name|applicant_name|xingming|xm|"
    r"phone_number|mobile_number|contact_phone|phone_no|tel_no|shouji|"
    r"phone|mobile|tel|cellphone|"
    r"email_address|contact_email|user_email|email|e_mail|mail|"
    r"id_card|id_no|identity_card|idcard|id_number|sfz|national_id|"
    r"bank_card|card_no|bank_account|account_no|card_number|bankcard|yinhangka|"
    r"passport|passport_no|huzhao|"
    r"license_plate|car_plate|vehicle_plate|plate_no|chepai|plate"
    r")\b",
    re.IGNORECASE,
)

# [Fix #3] 句末强自然语言标记：有这类才让结构化字段回落到非结构化。
# 避免短干净的地址/姓名被误判。
_SENTENCE_MARK_RE = re.compile(r"[。！？；]|\.\s|[,，]\s*\S+\s*[，,]")


def _is_pure_structured_field(field_name: str, value_str: str) -> bool:
    if not _STRUCTURED_FIELD_RE.search(field_name):
        return False
    # value 过长或含句末标点 → 可能混了自然语言，不走 structured 短路
    if len(value_str) > 120:
        return False
    if _SENTENCE_MARK_RE.search(value_str):
        return False
    return True


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
    # ── 1. 二进制数据 → OCR/文档解析 ────────────────────────────
    if _is_binary(value):
        return scan_blob_field(value, record_id, table_name, field_name, db_type, db_name)

    if value is None:
        return []

    value_str = str(value).strip()
    if not value_str:
        return []

    # ── 0. 噪声行快速跳过 ────────────────────────────────────────
    # README 明确: 噪声行的字段值为 "N/A_数字" 形式，不需要出现在 upload.csv。
    # 在此处过滤掉，避免下游扫描器浪费 CPU 预算(尤其避免长 "N/A_xxx"
    # 字串走进 unstructured 路径)。
    if _NOISE_VALUE_RE.match(value_str):
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
        # 解析失败：若像自然语言日志（如 "[2026-01-18 ...] 客服记录..."）
        # 走非结构化；否则才降级到结构化。避免 data_form 被错贴成 semi_structured
        # 导致官方分桶双扣分。
        if _looks_unstructured_after_parse_fail(value_str):
            return scan_unstructured_field(field_name, value_str, record_id,
                                            table_name, field_name, db_type, db_name)
        return scan_structured_field(field_name, value_str, record_id,
                                     table_name, field_name, db_type, db_name)

    # ── 4. XML → semi_structured（直接调用 XML 扫描器）────────────
    if _is_xml_like(value_str):
        hits = scan_xml_value(value_str, record_id, table_name,
                              field_name, db_type, db_name)
        if hits:
            return hits
        # XML 解析失败时同理，先看是不是自然语言文本
        if _looks_unstructured_after_parse_fail(value_str):
            return scan_unstructured_field(field_name, value_str, record_id,
                                            table_name, field_name, db_type, db_name)
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

    # ── 5a. [Fix #4] 字段名=encoded/payload/base64 但 value 不是真编码：
    # 走 structured 正则扫描后把 data_form 重标成 encoded，避免 form 标错。
    if _ENCODED_FIELD_RE.search(field_name):
        hits = scan_structured_field(field_name, value_str, record_id,
                                      table_name, field_name, db_type, db_name)
        for h in hits:
            h["data_form"] = "encoded"
        return hits

    # ── 5b. [Fix #3] 字段名=单实体结构化字段（full_address/real_name 等）时
    #       强制走 structured，不要让 is_unstructured_text 误判
    if _is_pure_structured_field(field_name, value_str):
        return scan_structured_field(field_name, value_str, record_id,
                                      table_name, field_name, db_type, db_name)

    # ── 6. 长自然语言文本 → unstructured_text ───────────────────
    if is_unstructured_text(value_str):
        return scan_unstructured_field(field_name, value_str, record_id,
                                        table_name, field_name, db_type, db_name)

    # ── 7. 默认 → structured ─────────────────────────────────────
    return scan_structured_field(field_name, value_str, record_id,
                                  table_name, field_name, db_type, db_name)
