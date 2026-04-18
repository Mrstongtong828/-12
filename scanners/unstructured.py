"""
非结构化自然语言文本扫描器。

策略：
  1. 正则扫描（始终运行，速度快）
  2. UIE NER（可选，模型存在时启用，结果与正则合并去重）
  UIE 不可用时自动降级为纯正则，不崩溃。
"""
import re
from core.patterns import (
    extract_sensitive_from_value, _SURNAMES_SET, COMPOUND_SURNAMES, NAME_BLACKLIST,
    _NAME_BLACKLIST_RE, _NAME_ADDR_CHARS,
    is_valid_address,              # [新增]
)
from core.config import SENSITIVE_LEVEL_MAP
from core.task_queue import ai_inference_slot

UIE_MODEL_DIR = "./models/paddlenlp/uie-base"
UIE_MAX_CHUNK = 500  # UIE 单次最大输入字符数，防 OOM（fix P6）

_uie_engine = None
_uie_available = None  # None=未检测, True/False=检测结果


def get_uie_engine():
    """单例加载 UIE，模型目录不存在或加载失败时返回 None。"""
    global _uie_engine, _uie_available
    if _uie_available is not None:
        return _uie_engine

    import os
    if not os.path.isdir(UIE_MODEL_DIR) or not os.listdir(UIE_MODEL_DIR):
        _uie_available = False
        return None

    try:
        from paddlenlp import Taskflow
        _uie_engine = Taskflow(
            "information_extraction",
            schema=["人名", "家庭住址", "手机号码", "身份证号", "银行卡号", "电子邮箱"],
            model="uie-base",
            task_path=UIE_MODEL_DIR,
            use_gpu=False,
        )
        _uie_available = True
        print("[INFO] UIE 模型加载成功")
    except Exception as e:
        print(f"[WARN] UIE 加载失败，使用正则兜底: {e}")
        _uie_available = False

    return _uie_engine


# 模块级预编译（fix P2/P3）
_NAME_TRIGGER = re.compile(
    r"(?:叫|名叫|姓名|姓名为|名字|名为|联系人|负责人|经手人|申请人|代理人)"
)
_ENCODED_HINT = re.compile(
    r"^[A-Za-z0-9+/=]{20,}$|%[0-9A-Fa-f]{2}|\\u[0-9a-fA-F]{4}"
)
_HAS_CHINESE = re.compile(r"[\u4e00-\u9fa5]")
_HAS_NATURAL = re.compile(r"[\s，。！？、；：\u201c\u201d\u2018\u2019（）【】]")
_CN_WORD = re.compile(r"[\u4e00-\u9fa5]{2,4}")

_VALID_TLD = re.compile(r'\.[a-zA-Z]{2,6}$')
_IP_PATH_PREFIX = re.compile(r'(?:/\d|:\d)')  # 匹配 /24 或 :8080 这类路径/端口

# 地址正则预编译（fix P2）
_ADDRESS_RE = re.compile(
    r"[\u4e00-\u9fa5]{2,}"
    r"(?:省|市|区|县|镇|乡|街道|路|街|巷|弄|号|栋|楼|室|单元|村|组|社区)"
    r"[\u4e00-\u9fa5\d\-]*"
    r"(?:(?:省|市|区|县|镇|乡|街道|路|街|巷|弄|号|栋|楼|室|单元|村|组|社区)"
    r"[\u4e00-\u9fa5\d\-]*)+"
)


def is_unstructured_text(value_str: str) -> bool:
    if not value_str or not isinstance(value_str, str):
        return False
    s = value_str.strip()
    # [F4] 阈值从 20 降到 10，避免漏掉"备注: 王五 13800138000"这类短文本
    if len(s) <= 10:
        return False
    if s.startswith(("{", "[", "<")):
        return False
    if _ENCODED_HINT.search(s):
        return False
    return bool(_HAS_CHINESE.search(s)) or bool(_HAS_NATURAL.search(s))


def _make_finding(db_type, db_name, table_name, field_col_name,
                  record_id, sensitive_type, extracted_value):
    level = SENSITIVE_LEVEL_MAP.get(sensitive_type, "L3")
    return {
        "db_type": db_type,
        "db_name": db_name,
        "table_name": table_name,
        "field_name": field_col_name,
        "record_id": record_id,
        "data_form": "unstructured_text",
        "sensitive_type": sensitive_type,
        "sensitive_level": level,
        "extracted_value": extracted_value,
    }


def _scan_chinese_names(text: str) -> list:
    """
    识别规则（fix B1/B5）：
      - 3-4 字名：姓氏匹配即可（准确率高）
      - 2 字名：必须有触发词上下文（避免"张力"/"王府"等 FP）
      - 复姓：前2字在 COMPOUND_SURNAMES 中视为4字名
    """
    results = []
    for m in _CN_WORD.finditer(text):
        name = m.group()
        if _NAME_BLACKLIST_RE.search(name):
            continue
        # [fix] 混入地址/机构用字 → 不是人名（防 '东门街道' '家庄市石'）
        if any(c in _NAME_ADDR_CHARS for c in name):
            continue

        is_surname_match = False
        # 单字姓
        if name[0] in _SURNAMES_SET:
            is_surname_match = True
        # 复姓（fix B5）
        elif len(name) >= 3 and name[:2] in COMPOUND_SURNAMES:
            is_surname_match = True

        if not is_surname_match:
            continue

        if len(name) >= 3:
            # 3-4 字名直接认定（fix B1：原来 len >= 2 永真）
            results.append(("CHINESE_NAME", name))
        else:
            # 2 字名需要触发词上下文
            ctx_start = max(0, m.start() - 10)
            ctx = text[ctx_start:m.start()]
            if _NAME_TRIGGER.search(ctx):
                results.append(("CHINESE_NAME", name))

    return results


def _scan_addresses(text: str) -> list:
    # [fix #8] 用统一校验，strict=False（长文本中地址常被分词打断，放宽长度到 10）
    return [
        ("ADDRESS", m.group())
        for m in _ADDRESS_RE.finditer(text)
        if is_valid_address(m.group(), strict=False)
    ]


# UIE schema 实体类型 → sensitive_type 映射
_UIE_TYPE_MAP = {
    "人名": "CHINESE_NAME",
    "家庭住址": "ADDRESS",
    "手机号码": "PHONE_NUMBER",
    "身份证号": "ID_CARD",
    "银行卡号": "BANK_CARD",
    "电子邮箱": "EMAIL",
}


def _run_uie(text: str) -> list:
    """调用 UIE 推理，超长文本分块处理（fix P6），受 AI 信号量保护。"""
    uie = get_uie_engine()
    if uie is None:
        return []

    results = []
    # 按 UIE_MAX_CHUNK 分块，避免超长文本 OOM
    chunks = [text[i:i + UIE_MAX_CHUNK] for i in range(0, len(text), UIE_MAX_CHUNK)]

    try:
        for chunk in chunks:
            with ai_inference_slot("uie"):
                raw = uie(chunk)
            if isinstance(raw, list) and raw:
                raw = raw[0]
            for zh_type, entities in raw.items():
                stype = _UIE_TYPE_MAP.get(zh_type)
                if not stype:
                    continue
                for ent in entities:
                    val = ent.get("text", "").strip()
                    if val:
                        results.append((stype, val))
    except Exception as e:
        print(f"[WARN] UIE 推理失败: {e}")

    return results


def _post_filter(findings: list, text: str) -> list:
    """过滤非结构化文本中 IP_ADDRESS 和 EMAIL 的误报。"""
    result = []
    for f in findings:
        stype = f.get("sensitive_type")
        val = f.get("extracted_value", "")
        if stype == "IP_ADDRESS":
            # 在原文中定位该值，检查其后是否紧跟 /数字 或 :数字（版本号/端口/CIDR）
            idx = text.find(val)
            if idx >= 0:
                after = text[idx + len(val):idx + len(val) + 4]
                if _IP_PATH_PREFIX.match(after):
                    continue
        elif stype == "EMAIL":
            # 域名部分必须有合法 TLD
            if not _VALID_TLD.search(val):
                continue
        result.append(f)
    return result


def scan_unstructured_field(field_name, value_str, record_id,
                             table_name, field_col_name, db_type, db_name):
    if not value_str or not isinstance(value_str, str):
        return []

    findings = []
    seen = set()

    def _add(stype, val):
        key = (stype, val)
        if key not in seen:
            seen.add(key)
            findings.append(_make_finding(
                db_type, db_name, table_name, field_col_name,
                record_id, stype, val,
            ))

    # 正则扫描（排除姓名/地址，用更精准的专项逻辑处理）
    for stype, val in extract_sensitive_from_value(value_str):
        if stype not in ("CHINESE_NAME", "ADDRESS"):
            _add(stype, val)

    # 中文姓名（上下文+字长双重过滤，fix B1）
    for stype, val in _scan_chinese_names(value_str):
        _add(stype, val)

    # 地址（预编译正则，fix P2）
    for stype, val in _scan_addresses(value_str):
        _add(stype, val)

    # UIE NER（分块处理，fix P6）
    for stype, val in _run_uie(value_str):
        _add(stype, val)

    findings = _post_filter(findings, value_str)
    return findings
