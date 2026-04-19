import json
import xml.etree.ElementTree as ET

from core.config import SENSITIVE_LEVEL_MAP, LEAF_TEXT_MAX_LEN
from core.patterns import (
    extract_sensitive_from_value, match_field_name,
    extract_by_field_hint,
    is_valid_address,              # [新增]
    is_name_fp_field,              # [FP-fix P0-A]
    _SURNAMES_SET, NAME_BLACKLIST, _FIELD_NAME_COMPILED, _NAME_BLACKLIST_RE,
)

# 提升到模块级,避免 _walk 递归时每次 lazy import
try:
    from scanners.encoded import _is_encoded_value as _enc_check, decode_recursive as _dec_recursive
except ImportError:
    _enc_check = None
    _dec_recursive = None

PASSWORD_FIELD_KEYWORDS = {"password", "passwd", "pwd", "secret", "token",
                            "api_key", "apikey", "private_key", "secret_key",
                            "access_token", "auth_token", "refresh_token",
                            "credential"}


def _is_password_field(field_name: str) -> bool:
    fn = field_name.lower()
    return any(kw in fn for kw in PASSWORD_FIELD_KEYWORDS)


def _make_finding(db_type, db_name, table_name, field_col_name,
                  record_id, data_form, sensitive_type, extracted_value):
    level = SENSITIVE_LEVEL_MAP.get(sensitive_type, "L3")
    return {
        "db_type": db_type,
        "db_name": db_name,
        "table_name": table_name,
        "field_name": field_col_name,
        "record_id": record_id,
        "data_form": data_form,
        "sensitive_type": sensitive_type,
        "sensitive_level": level,
        "extracted_value": extracted_value,
    }


def _detect_form(value_str: str) -> str:
    s = value_str.strip()
    if s.startswith(("{", "[")):
        return "semi_structured"
    if s.startswith("<"):
        return "semi_structured"
    return "structured"


def scan_json_value(json_str, record_id, table_name, field_col_name, db_type, db_name):
    findings = []
    try:
        data = json.loads(json_str)
    except Exception:
        return findings

    def _walk(obj, parent_key=None):
        # [FP-fix P0-A] 使用最近的父键作为有效字段名。
        # 这样 ext_json 内部的 {"handler": "张警官"} 也能命中字段黑名单。
        effective_field = parent_key if parent_key else field_col_name

        if isinstance(obj, str):
            actual = obj
            if _enc_check is not None and _enc_check(obj):
                decoded, chain = _dec_recursive(obj)
                if chain:
                    actual = decoded
            # [性能 #12] JSON 叶子过长时截断
            if len(actual) > LEAF_TEXT_MAX_LEN:
                actual = actual[:LEAF_TEXT_MAX_LEN]
            for stype, val in extract_sensitive_from_value(actual):
                if stype == "CHINESE_NAME" and is_name_fp_field(effective_field):
                    continue
                findings.append(_make_finding(
                    db_type, db_name, table_name, field_col_name,
                    record_id, "semi_structured", stype, val,
                ))
        elif isinstance(obj, (int, float)):
            # [B1] JSON 数字类型(如 {"phone": 13800138000})也需扫描
            s = str(int(obj)) if isinstance(obj, float) and obj == int(obj) else str(obj)
            for stype, val in extract_sensitive_from_value(s):
                if stype == "CHINESE_NAME" and is_name_fp_field(effective_field):
                    continue
                findings.append(_make_finding(
                    db_type, db_name, table_name, field_col_name,
                    record_id, "semi_structured", stype, val,
                ))
        elif isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and _is_password_field(k):
                    findings.append(_make_finding(
                        db_type, db_name, table_name, field_col_name,
                        record_id, "semi_structured", "PASSWORD_OR_SECRET", v,
                    ))
                else:
                    _walk(v, parent_key=k)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, parent_key=parent_key)

    _walk(data)
    return findings


def scan_xml_value(xml_str, record_id, table_name, field_col_name, db_type, db_name):
    findings = []
    try:
        root = ET.fromstring(xml_str)
    except Exception:
        return findings

    def _walk_elem(elem):
        tag_name = elem.tag if elem.tag else field_col_name
        if elem.text and elem.text.strip():
            for stype, val in extract_sensitive_from_value(elem.text.strip()):
                if stype == "CHINESE_NAME" and is_name_fp_field(tag_name):
                    continue
                findings.append(_make_finding(
                    db_type, db_name, table_name, field_col_name,
                    record_id, "semi_structured", stype, val,
                ))
        for attr_name, attr_val in elem.attrib.items():
            for stype, val in extract_sensitive_from_value(attr_val):
                if stype == "CHINESE_NAME" and is_name_fp_field(attr_name):
                    continue
                findings.append(_make_finding(
                    db_type, db_name, table_name, field_col_name,
                    record_id, "semi_structured", stype, val,
                ))
        for child in elem:
            _walk_elem(child)

    _walk_elem(root)
    return findings


def _regex_fallback_scan(value_str, field_name, record_id, table_name,
                        field_col_name, db_type, db_name, data_form):
    findings = []
    field_hints = None

    for stype, val in extract_sensitive_from_value(value_str):
        if stype == "CHINESE_NAME":
            if is_name_fp_field(field_name):
                continue
            if field_hints is None:
                field_hints = match_field_name(field_name)
            if "CHINESE_NAME" not in field_hints:
                if not (len(val) >= 2
                        and val[0] in _SURNAMES_SET
                        and not _NAME_BLACKLIST_RE.search(val)):
                    continue
        elif stype == "ADDRESS":
            if not is_valid_address(val, strict=True):
                continue

        findings.append(_make_finding(
            db_type, db_name, table_name, field_col_name,
            record_id, data_form, stype, val,
        ))

    for stype, val in extract_by_field_hint(field_name, value_str):
        findings.append(_make_finding(
            db_type, db_name, table_name, field_col_name,
            record_id, data_form, stype, val,
        ))

    return findings


def scan_structured_field(field_name, value, record_id, table_name,
                           field_col_name, db_type, db_name):
    if value is None:
        return []

    value_str = str(value).strip()
    if not value_str:
        return []

    if _is_password_field(field_name):
        return [_make_finding(
            db_type, db_name, table_name, field_col_name,
            record_id, "structured", "PASSWORD_OR_SECRET", value_str,
        )]

    data_form = _detect_form(value_str)

    if data_form == "semi_structured":
        s = value_str.strip()
        if s.startswith("<"):
            results = scan_xml_value(value_str, record_id, table_name,
                                     field_col_name, db_type, db_name)
        else:
            results = scan_json_value(value_str, record_id, table_name,
                                      field_col_name, db_type, db_name)
        if results:
            return results
        return _regex_fallback_scan(
            value_str, field_name, record_id, table_name,
            field_col_name, db_type, db_name,
            data_form="semi_structured",
        )

    return _regex_fallback_scan(
        value_str, field_name, record_id, table_name,
        field_col_name, db_type, db_name,
        data_form="structured",
    )
