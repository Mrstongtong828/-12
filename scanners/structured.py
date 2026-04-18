import json
# structured.py 顶部的 import 追加一项
from core.config import SENSITIVE_LEVEL_MAP, LEAF_TEXT_MAX_LEN
import xml.etree.ElementTree as ET
from core.patterns import (
    extract_sensitive_from_value, match_field_name,
    extract_by_field_hint,
    is_valid_address,              # [新增]
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

    def _walk(obj):
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


def _regex_fallback_scan(value_str, field_name, record_id, table_name,
                        field_col_name, db_type, db_name, data_form):
    """
    通用正则兜底扫描逻辑。从 value_str 里提取所有敏感值，并应用：
      - CHINESE_NAME 保留条件（字段名提示或首字为已知姓氏）
      - ADDRESS 保留条件（长度 >=15，同时含行政单位和街道词）
      - extract_by_field_hint（营业执照等只在字段名命中时才识别的类型）

    data_form 由调用方决定：走 semi_structured fallback 时传 "semi_structured"，
    走默认结构化扫描时传 "structured"。
    """
    findings = []

    # 只在需要时计算 field_hints（CHINESE_NAME 过滤才用得到）
    field_hints = None

    for stype, val in extract_sensitive_from_value(value_str):
        if stype == "CHINESE_NAME":
            if field_hints is None:
                field_hints = match_field_name(field_name)
            if "CHINESE_NAME" not in field_hints:
                # 字段名未命中时，要求首字为已知姓氏且不在黑名单
                if not (len(val) >= 2
                        and val[0] in _SURNAMES_SET
                        and not _NAME_BLACKLIST_RE.search(val)):
                    continue
        elif stype == "ADDRESS":
            # [fix #8] 用统一函数，strict=True（结构化字段要求严格）
            if not is_valid_address(val, strict=True):
                continue

        findings.append(_make_finding(
            db_type, db_name, table_name, field_col_name,
            record_id, data_form, stype, val,
        ))

    # [新增] 字段名命中时才触发的敏感类型（当前为 BUSINESS_LICENSE_NO）
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

    # 密码字段：整值即为敏感值
    if _is_password_field(field_name):
        return [_make_finding(
            db_type, db_name, table_name, field_col_name,
            record_id, "structured", "PASSWORD_OR_SECRET", value_str,
        )]

    data_form = _detect_form(value_str)

    # ── 半结构化分支 ──────────────────────────────────────────────
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
        # [bug #4 修复] 解析失败时 fallback 走正则，但保留 semi_structured 标签，
        # 否则伪 JSON/XML 串会被错误分类到 structured 形态，TP 全变 FP+FN
        return _regex_fallback_scan(
            value_str, field_name, record_id, table_name,
            field_col_name, db_type, db_name,
            data_form="semi_structured",
        )

    # ── 结构化默认分支 ────────────────────────────────────────────
    return _regex_fallback_scan(
        value_str, field_name, record_id, table_name,
        field_col_name, db_type, db_name,
        data_form="structured",
    )
