import re

from scanners.structured import scan_structured_field
from scanners.encoded import (
    scan_encoded_field,
    _is_encoded_value,
    try_base64_as_image,
)
from scanners.unstructured import scan_unstructured_field, is_unstructured_text
from scanners.blob import scan_blob_field

_NOISE_VALUE_RE = re.compile(r"^N/A_\d+$")
_HEX_CHARS_DISPATCH = re.compile(r'^[0-9a-fA-F]+$')

_PWD_FIELD_RE = re.compile(
    r"\b(?:password|passwd|pass|pwd|secret|token|api_key|apikey|"
    r"access_key|secret_key|private_key|auth_token|refresh_token|"
    r"access_token|credential|pin)\b",
    re.IGNORECASE,
)

_ENCODED_FIELD_RE = re.compile(
    r"\b(?:encoded[_\w]*|payload|base64|encode|cipher|ciphertext|encrypted)\b",
    re.IGNORECASE,
)

_JSON_FIELD_RE = re.compile(
    r"(?:"
    r"\b\w*_json\b|"
    r"\bjson\b|"
    r"\bclaim_data\b|\brisk_data\b|\bext_data\b|"
    r"\bmeta_data\b|\bmetadata\b|\bpayload_data\b|"
    r"\bprofile_data\b|\bextra_data\b|"
    r"\bapp_data\b"
    r")",
    re.IGNORECASE,
)

_HAS_CHINESE_DISPATCH = re.compile(r"[\u4e00-\u9fa5]")
_HAS_NATURAL_DISPATCH = re.compile(r"[\s,。！？、；：\u201c\u201d\u2018\u2019（）【】]")


def _looks_unstructured_after_parse_fail(s: str) -> bool:
    if not s or len(s) <= 10:
        return False
    return bool(_HAS_CHINESE_DISPATCH.search(s)) or bool(_HAS_NATURAL_DISPATCH.search(s))


_STRUCTURED_FIELD_RE = re.compile(
    r"\b(?:"
    r"full_address|home_address|residence|addr|address|dizhi|"
    r"domicile|hukou|huji|"
    r"real_name|true_name|customer_name|user_name|full_name|person_name|"
    r"client_name|owner_name|contact_name|applicant_name|"
    r"consignee|holder_name|patient_name|"
    r"xingming|xm|"
    r"phone_number|mobile_number|contact_phone|phone_no|tel_no|shouji|"
    r"phone|mobile|tel|cellphone|"
    r"email_address|contact_email|user_email|email|e_mail|mail|"
    r"id_card|id_no|identity_card|idcard|id_number|sfz|national_id|id_verify|"
    r"bank_card|card_no|bank_account|account_no|card_number|bankcard|yinhangka|"
    r"passport|passport_no|huzhao|"
    r"license_plate|car_plate|vehicle_plate|plate_no|chepai|plate|"
    r"vin|vin_code|"
    r"hf_no|ss_no|medical_record_no"
    r")\b",
    re.IGNORECASE,
)

_SENTENCE_MARK_RE = re.compile(r"[。！？；]|\.\s|[,，]\s*\S+\s*[,，]")


def _is_pure_structured_field(field_name: str, value_str: str) -> bool:
    if not _STRUCTURED_FIELD_RE.search(field_name):
        return False
    if len(value_str) > 120:
        return False
    if _SENTENCE_MARK_RE.search(value_str):
        return False
    return True


def _is_binary(value) -> bool:
    return isinstance(value, (bytes, bytearray, memoryview))


def _is_json_like(s: str) -> bool:
    return s.lstrip().startswith(("{", "["))


def _is_xml_like(s: str) -> bool:
    return s.lstrip().startswith("<")


def _relabel_form(hits: list, target_form: str) -> list:
    for h in hits:
        h["data_form"] = target_form
    return hits


def dispatch(field_name: str, value, record_id, table_name: str,
             db_type: str, db_name: str) -> list:
    """
    核心调度管线:只管路由 + 最终 data_form 打标。
    值的具体解析(JSON/XML/正则)统一下沉到 scan_structured_field 内部的
    _detect_form 分支,dispatcher 不再自己调 scan_json_value/scan_xml_value。
    """
    # 0. 空值/二进制/噪声
    if value is None:
        return []
    if _is_binary(value):
        return scan_blob_field(value, record_id, table_name, field_name, db_type, db_name)

    value_str = str(value).strip()
    if not value_str or _NOISE_VALUE_RE.match(value_str):
        return []

    # 1. 伪装层穿透(Hex bytes / Base64 Image)
    if (value_str.startswith(r'\x') and len(value_str) > 4
            and (len(value_str) - 2) % 2 == 0
            and _HEX_CHARS_DISPATCH.match(value_str[2:])):
        return scan_blob_field(value_str, record_id, table_name, field_name, db_type, db_name)

    if 100 <= len(value_str) <= 10_000_000 and ' ' not in value_str and '\n' not in value_str:
        img_bytes = try_base64_as_image(value_str)
        if img_bytes is not None:
            return scan_blob_field(img_bytes, record_id, table_name, field_name, db_type, db_name)

    # 2. 密码字段极速通道 → 强制 structured
    # [修复] 不能裸返回,scan_structured_field 可能把 {} 开头值标成 semi_structured
    if _PWD_FIELD_RE.search(field_name):
        hits = scan_structured_field(field_name, value_str, record_id,
                                      table_name, field_name, db_type, db_name)
        return _relabel_form(hits, "structured")

    is_encoded_field = bool(_ENCODED_FIELD_RE.search(field_name))
    is_json_field = bool(_JSON_FIELD_RE.search(field_name))
    is_json_val = _is_json_like(value_str)
    is_xml_val = _is_xml_like(value_str)

    # 3. 编码层:字段名或值触发都走 encoded 扫描器
    if is_encoded_field or _is_encoded_value(value_str):
        hits = scan_encoded_field(field_name, value_str, record_id,
                                   table_name, field_name, db_type, db_name)
        if hits:
            # [修复] 确保标签是 encoded(scan_encoded_field 内部 _scan_decoded
            # 走 JSON 子分支时可能被其它形态覆盖)
            return _relabel_form(hits, "encoded")

        # 编码字段解码失败 → 明文键值对兜底(如 "BANK_CARD:xxx|PHONE:yyy")
        if is_encoded_field:
            hits = scan_structured_field(field_name, value_str, record_id,
                                          table_name, field_name, db_type, db_name)
            return _relabel_form(hits, "encoded")
        # _is_encoded_value=True 但不是编码字段 → 继续往下走,让后续分支兜底

    # 4. 半结构化:值是 JSON/XML 或字段名暗示 JSON 容器
    if is_json_val or is_xml_val or is_json_field:
        hits = scan_structured_field(field_name, value_str, record_id,
                                      table_name, field_name, db_type, db_name)
        if hits:
            # scan_structured_field 内部 _detect_form 已把 JSON/XML 形态标成 semi_structured
            # 但 "字段名是 _json 但值不是 JSON-like"(被损坏/空字符串样) 会标成 structured
            # 这种情况强制标回 semi_structured,避免官方双重扣分
            if is_json_field and not (is_json_val or is_xml_val):
                return _relabel_form(hits, "semi_structured")
            return hits

        # JSON/XML 解析失败且值是大段自然语言 → 交给非结构化引擎
        if _looks_unstructured_after_parse_fail(value_str):
            hits = scan_unstructured_field(field_name, value_str, record_id,
                                            table_name, field_name, db_type, db_name)
            # [修复] 字段名暗示 JSON 容器时保持 semi_structured,
            # 否则保持 unstructured_text(由扫描器自己标)
            if is_json_field:
                return _relabel_form(hits, "semi_structured")
            return hits
        return []

    # 5. 单实体结构化字段(姓名/手机/身份证等)
    if _is_pure_structured_field(field_name, value_str):
        hits = scan_structured_field(field_name, value_str, record_id,
                                      table_name, field_name, db_type, db_name)
        return _relabel_form(hits, "structured")

    # 6. 长自然语言
    if is_unstructured_text(value_str) or _looks_unstructured_after_parse_fail(value_str):
        hits = scan_unstructured_field(field_name, value_str, record_id,
                                        table_name, field_name, db_type, db_name)
        return _relabel_form(hits, "unstructured_text")

    # 7. 终极兜底 → structured
    hits = scan_structured_field(field_name, value_str, record_id,
                                  table_name, field_name, db_type, db_name)
    return _relabel_form(hits, "structured")
