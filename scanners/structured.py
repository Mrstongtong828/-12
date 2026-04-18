import json
import xml.etree.ElementTree as ET
from core.patterns import (
    extract_sensitive_from_value, match_field_name,
    _SURNAMES_SET, NAME_BLACKLIST, _FIELD_NAME_COMPILED, _NAME_BLACKLIST_RE,
)
from core.config import SENSITIVE_LEVEL_MAP

# 提升到模块级，避免 _walk 递归时每次 lazy import
try:
    from scanners.encoded import _is_encoded_value as _enc_check, decode_recursive as _dec_recursive
except ImportError:
    _enc_check = None
    _dec_recursive = None

PASSWORD_FIELD_KEYWORDS = {"password", "passwd", "pwd", "secret", "token",
                            "api_key", "apikey", "private_key", "secret_key",
                            "access_token", "auth_token"}


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

    def _walk(obj):
        if isinstance(obj, str):
            actual = obj
            if _enc_check is not None and _enc_check(obj):
                decoded, chain = _dec_recursive(obj)
                if chain:
                    actual = decoded
            for stype, val in extract_sensitive_from_value(actual):
                findings.append(_make_finding(
                    db_type, db_name, table_name, field_col_name,
                    record_id, "semi_structured", stype, val,
                ))
        elif isinstance(obj, (int, float)):
            # [B1] JSON 数字类型（如 {"phone": 13800138000}）也需扫描
            s = str(int(obj)) if isinstance(obj, float) and obj == int(obj) else str(obj)
            for stype, val in extract_sensitive_from_value(s):
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
                    _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return findings


def scan_xml_value(xml_str, record_id, table_name, field_col_name, db_type, db_name):
    findings = []
    try:
        root = ET.fromstring(xml_str)
    except Exception:
        return findings

    def _walk_elem(elem):
        if elem.text and elem.text.strip():
            for stype, val in extract_sensitive_from_value(elem.text.strip()):
                findings.append(_make_finding(
                    db_type, db_name, table_name, field_col_name,
                    record_id, "semi_structured", stype, val,
                ))
        for attr_val in elem.attrib.values():
            for stype, val in extract_sensitive_from_value(attr_val):
                findings.append(_make_finding(
                    db_type, db_name, table_name, field_col_name,
                    record_id, "semi_structured", stype, val,
                ))
        for child in elem:
            _walk_elem(child)

    _walk_elem(root)
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
        # [B2] fallback：伪 JSON/XML 解析失败时走正则扫描
        if results:
            return results
        # 解析失败，降级为正则扫描（继续执行后续逻辑）

    findings = []
    all_hits = extract_sensitive_from_value(value_str)
    for stype, val in all_hits:
        if stype == "CHINESE_NAME":
            # 保留条件：字段名提示是姓名字段，或首字是已知姓氏
            field_hints = match_field_name(field_name)
            if "CHINESE_NAME" not in field_hints:
                if not (len(val) >= 2 and val[0] in _SURNAMES_SET and not _NAME_BLACKLIST_RE.search(val)):
                    continue
        elif stype == "ADDRESS":
            # 保留条件：长度 >= 15，且同时含行政单位词和街道词
            _admin = set("省市区县")
            _street = set("路街巷弄号栋楼室")
            if len(val) < 15:
                continue
            if not any(c in _admin for c in val):
                continue
            if not any(c in _street for c in val):
                continue
        findings.append(_make_finding(
            db_type, db_name, table_name, field_col_name,
            record_id, "structured", stype, val,
        ))
    return findings
