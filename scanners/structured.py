import json
import xml.etree.ElementTree as ET

from core.config import SENSITIVE_LEVEL_MAP, LEAF_TEXT_MAX_LEN
from core.patterns import (
    extract_sensitive_from_value, match_field_name,
    extract_by_field_hint,
    is_valid_address,
    is_name_fp_field,
    is_job_title_name,
    COMPOUND_SURNAMES,
    _SURNAMES_SET, NAME_BLACKLIST, _FIELD_NAME_COMPILED, _NAME_BLACKLIST_RE,
    _NAME_ADDR_CHARS,
)

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


def _try_match_short_name(value: str, effective_field: str):
    """
    JSON/XML 叶子 2-4 字纯中文值短名兜底。
    救 try_name_at 不处理的 2 字名(石香/谈凯/向侃 等)。
    """
    v = value.strip() if isinstance(value, str) else ""
    if not (2 <= len(v) <= 4):
        return None
    if not all('\u4e00' <= c <= '\u9fa5' for c in v):
        return None
    if _NAME_BLACKLIST_RE.search(v):
        return None
    if any(c in _NAME_ADDR_CHARS for c in v):
        return None
    if is_job_title_name(v):
        return None
    
    # 【修复 3】复姓安全校验，防止数组越界和漏判
    has_anchor = (v[0] in _SURNAMES_SET) or (len(v) >= 2 and v[:2] in COMPOUND_SURNAMES)
    if not has_anchor:
        return None
        
    hints = match_field_name(effective_field)
    if "CHINESE_NAME" not in hints:
        return None
        
    return v


def scan_json_value(json_str, record_id, table_name, field_col_name, db_type, db_name):
    findings = []
    # 【修复 2】引入局部去重器，防止同一JSON内相同的敏感词多次被重复写入
    seen = set()
    
    try:
        data = json.loads(json_str)
    except Exception:
        return findings

    def _add(stype, val):
        key = (stype, val)
        if key not in seen:
            seen.add(key)
            findings.append(_make_finding(
                db_type, db_name, table_name, field_col_name,
                record_id, "semi_structured", stype, val
            ))

    def _walk(obj, parent_key=None):
        effective_field = parent_key if parent_key else field_col_name

        if isinstance(obj, str):
            actual = obj
            if _enc_check is not None and _enc_check(obj):
                decoded, chain = _dec_recursive(obj)
                if chain:
                    actual = decoded
            if len(actual) > LEAF_TEXT_MAX_LEN:
                actual = actual[:LEAF_TEXT_MAX_LEN]
                
            for stype, val in extract_sensitive_from_value(actual):
                if stype == "CHINESE_NAME" and is_name_fp_field(effective_field):
                    continue
                _add(stype, val)
                
            # 短名兜底
            short = _try_match_short_name(actual, effective_field)
            if short:
                _add("CHINESE_NAME", short)
                
        elif isinstance(obj, (int, float)):
            s = str(int(obj)) if isinstance(obj, float) and obj == int(obj) else str(obj)
            for stype, val in extract_sensitive_from_value(s):
                if stype == "CHINESE_NAME" and is_name_fp_field(effective_field):
                    continue
                _add(stype, val)
                
        elif isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and _is_password_field(k):
                    _add("PASSWORD_OR_SECRET", v)
                else:
                    _walk(v, parent_key=k)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, parent_key=parent_key)

    _walk(data)
    return findings


def scan_xml_value(xml_str, record_id, table_name, field_col_name, db_type, db_name):
    findings = []
    # 【修复 2】同理，XML也需要局部去重器
    seen = set()
    
    try:
        root = ET.fromstring(xml_str)
    except Exception:
        return findings

    def _add(stype, val):
        key = (stype, val)
        if key not in seen:
            seen.add(key)
            findings.append(_make_finding(
                db_type, db_name, table_name, field_col_name,
                record_id, "semi_structured", stype, val
            ))

    def _walk_elem(elem):
        tag_name = elem.tag if elem.tag else field_col_name
        if elem.text and elem.text.strip():
            text = elem.text.strip()
            for stype, val in extract_sensitive_from_value(text):
                if stype == "CHINESE_NAME" and is_name_fp_field(tag_name):
                    continue
                _add(stype, val)
                
            short = _try_match_short_name(text, tag_name)
            if short:
                _add("CHINESE_NAME", short)
                
        for attr_name, attr_val in elem.attrib.items():
            for stype, val in extract_sensitive_from_value(attr_val):
                if stype == "CHINESE_NAME" and is_name_fp_field(attr_name):
                    continue
                _add(stype, val)
                
        for child in elem:
            _walk_elem(child)

    _walk_elem(root)
    return findings


def _regex_fallback_scan(value_str, field_name, record_id, table_name,
                        field_col_name, db_type, db_name, data_form):
    findings = []
    field_hints = None
    emitted_names = set()

    for stype, val in extract_sensitive_from_value(value_str):
        if stype == "CHINESE_NAME":
            if is_name_fp_field(field_name):
                continue
            if field_hints is None:
                field_hints = match_field_name(field_name)
            if "CHINESE_NAME" not in field_hints:
                # 【修复 3】加上了对复姓的支持，防止漏杀
                has_anchor = (val[0] in _SURNAMES_SET) or (len(val) >= 2 and val[:2] in COMPOUND_SURNAMES)
                if not (len(val) >= 2 and has_anchor and not _NAME_BLACKLIST_RE.search(val)):
                    continue
            emitted_names.add(val)
            
        # 【修复 1】彻底删除了此处自作主张的 ADDRESS strict 过滤拦截！
        # 让 extract_sensitive_from_value 内部的智能判断说了算，不再做二次截杀。

        findings.append(_make_finding(
            db_type, db_name, table_name, field_col_name,
            record_id, data_form, stype, val,
        ))

    # Structured纯文本短名（如张三）最后兜底防漏
    if (data_form == "structured"
            and 2 <= len(value_str) <= 4
            and value_str not in emitted_names
            and not is_name_fp_field(field_name)
            and all('\u4e00' <= c <= '\u9fa5' for c in value_str)
            and not _NAME_BLACKLIST_RE.search(value_str)
            and not is_job_title_name(value_str)):
            
        if field_hints is None:
            field_hints = match_field_name(field_name)
        if "CHINESE_NAME" in field_hints:
            has_surname_anchor = (
                value_str[0] in _SURNAMES_SET
                or value_str[:2] in COMPOUND_SURNAMES
            )
            if has_surname_anchor:
                findings.append(_make_finding(
                    db_type, db_name, table_name, field_col_name,
                    record_id, data_form, "CHINESE_NAME", value_str,
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
