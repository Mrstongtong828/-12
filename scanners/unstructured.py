"""
非结构化自然语言文本扫描器。

策略：
  1. 正则扫描（始终运行，速度快）
  2. UIE NER（可选，由环境变量 UIE_ENABLED 开启，模型文件存在时才生效）
     - 默认关闭：UIE 正确率/覆盖率不稳定，先跑正则基线
     - UIE_AUDIT=1：UIE 结果不合并到 findings，只打日志供对比
     - schema 已裁剪为只抽 4 种有结构先验的实体（手机/身份证/银行卡/邮箱）
       人名/地址 UIE 易 FP 且正则+词典已经够好，不开
  UIE 不可用时自动降级为纯正则，不崩溃。

启用方式：
    export UIE_ENABLED=1               # 合并 UIE 结果
    export UIE_ENABLED=1 UIE_AUDIT=1   # 审计模式：只打日志不合并
"""
import os
import re
import logging
from core.patterns import (
    extract_sensitive_from_value, _SURNAMES_SET, COMPOUND_SURNAMES, NAME_BLACKLIST,
    _NAME_BLACKLIST_RE, _NAME_ADDR_CHARS,
    is_valid_address,
    clean_address_prefix,         # [Addr-Clean]
    is_name_fp_field,              # [P0-A]
    is_job_title_name,             # [P0-B]
    _is_verbish_name,              # [P0-D]
    try_name_at,                   # [Fix #1]
    _is_valid_name_shape,          # [Fix #1]
    _NAME_FOLLOW_VERB_BIGRAMS,     # [Fix #1] 2 字名后溢出检测用
)
from core.config import SENSITIVE_LEVEL_MAP
from core.task_queue import ai_inference_slot

UIE_MODEL_DIR = "./models/paddlenlp/uie-base"
UIE_MAX_CHUNK = 500  # UIE 单次最大输入字符数，防 OOM

# ── UIE 开关 ──────────────────────────────────────────────────────
# 默认关。审计模式把 UIE 输出打到 scan_error.log 让你判断是否值得开。
UIE_ENABLED = os.environ.get("UIE_ENABLED", "0") == "1"
UIE_AUDIT   = os.environ.get("UIE_AUDIT", "0") == "1"

_uie_logger = logging.getLogger("scan.uie")

_uie_engine = None
_uie_available = None  # None=未检测, True/False=检测结果


def get_uie_engine():
    """单例加载 UIE，模型目录不存在或加载失败时返回 None。"""
    global _uie_engine, _uie_available
    if _uie_available is not None:
        return _uie_engine

    if not os.path.isdir(UIE_MODEL_DIR) or not os.listdir(UIE_MODEL_DIR):
        _uie_available = False
        return None

    try:
        from paddlenlp import Taskflow
        _uie_engine = Taskflow(
            "information_extraction",
            # 裁剪后的 schema：只保留 4 种有结构先验的实体
            # 人名 / 家庭住址 UIE 易 FP，正则+词典已经够好，不开
            schema=["手机号码", "身份证号", "银行卡号", "电子邮箱"],
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


# 模块级预编译
_NAME_TRIGGER = re.compile(
    r"(?:叫|名叫|姓名|姓名为|名字|名为|联系人|负责人|经手人|申请人|代理人|"
    r"用户|客户|顾客|乘客|接待|办理|来电|反馈|咨询|投诉|患者|申报人|"
    # [Name-2字扩容] 让"翟琸来电"/"居黎咨询"这类 2 字名能被后置触发词命中。
    # 注意：_NAME_TRIGGER 目前只检查 name **之前**的 10 字窗口——加的是"触发词 +
    # 名字"顺序；"名字 + 触发词"是另一种顺序，属独立改动未做。
    r"反馈者|报案人|诉求人|咨询人|办理人|来电人|投诉人|申报者)"
)
_ENCODED_HINT = re.compile(
    r"^[A-Za-z0-9+/=]{20,}$|%[0-9A-Fa-f]{2}|\\u[0-9a-fA-F]{4}"
)
_HAS_CHINESE = re.compile(r"[\u4e00-\u9fa5]")
_HAS_NATURAL = re.compile(r"[\s,。！？、；：\u201c\u201d\u2018\u2019（）【】]")
_CN_WORD = re.compile(r"[\u4e00-\u9fa5]{2,4}")

_VALID_TLD = re.compile(r'\.[a-zA-Z]{2,6}$')
 #只过滤 CIDR(/后跟 1-2 位数字,如 /24),不过滤 :端口
_IP_CIDR_SUFFIX = re.compile(r'^/\d{1,2}(?!\d)')
# 还要过滤版本号模式: IP 紧跟 . 或 - 表示它不是真 IP(如 "v1.2.3.4.5" 截出的 1.2.3.4)
_IP_VERSION_SUFFIX = re.compile(r'^[.\-]\d')

# 地址正则预编译
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
    # 阈值 10：避免漏掉"备注: 王五 13800138000"这类短文本
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
    [Fix #1] 姓氏锚点扫描：
      - 3-4 字名：姓氏锚定 + 4 字末尾溢出保护（"牧涵育先生" → 取 "牧涵育"）
      - 2 字名：姓氏锚定 + 触发词上下文
      - 复姓：前 2 字在 COMPOUND_SURNAMES → 允许 3-4 字
    避免了旧 `{2,4}` 贪婪正则把 "姓名翟琸" 整块吃进去导致漏抓的问题。
    """
    results = []
    emitted = set()
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        has_anchor = (c in _SURNAMES_SET
                      or (i + 2 <= n and text[i:i+2] in COMPOUND_SURNAMES))
        if not has_anchor:
            i += 1
            continue

        # 先试 4/3 字直接通过（无需触发词）
        name, consumed = try_name_at(text, i)
        if name:
            if name not in emitted:
                emitted.add(name)
                results.append(("CHINESE_NAME", name))
            i += consumed
            continue

        # 再试 2 字名（需触发词上下文）
        if i + 2 <= n:
            cand = text[i:i+2]
            if (all('\u4e00' <= ch <= '\u9fa5' for ch in cand)
                    and _is_valid_name_shape(cand)):
                # [2字名] 接受两种触发方向：
                #   ① 前置触发词：客户/申请人/姓名 叫 xxx → 窗口 = [i-10, i)
                #   ② 后置触发词：xxx 来电/咨询/反馈 → 窗口 = [i+2, i+12)
                # 任一方向命中即接受。
                ctx_before = text[max(0, i - 10):i]
                ctx_after  = text[i + 2:min(n, i + 12)]
                if _NAME_TRIGGER.search(ctx_before) or _NAME_TRIGGER.search(ctx_after):
                    if cand not in emitted:
                        emitted.add(cand)
                        results.append(("CHINESE_NAME", cand))
                    i += 2
                    continue
        i += 1
    return results


def _scan_addresses(text: str) -> list:
    # 长文本中地址常被分词打断，放宽长度到 10；核心校验由 is_valid_address 统一做
    # [Addr-Clean] 命中后调用 clean_address_prefix 剥掉"我家在/家住/现居/..."
    results = []
    for m in _ADDRESS_RE.finditer(text):
        addr = clean_address_prefix(m.group())
        if is_valid_address(addr, strict=False):
            results.append(("ADDRESS", addr))
    return results


# UIE schema 实体类型 → sensitive_type 映射
# 注意：schema 已裁剪，这里同步只保留 4 种
_UIE_TYPE_MAP = {
    # "人名":     "CHINESE_NAME",   # [裁剪] 正则+姓氏词典已够用，UIE 易 FP
    # "家庭住址": "ADDRESS",        # [裁剪] 同上
    "手机号码":  "PHONE_NUMBER",
    "身份证号":  "ID_CARD",
    "银行卡号":  "BANK_CARD",
    "电子邮箱":  "EMAIL",
}


def _run_uie(text: str) -> list:
    """
    调用 UIE 推理。
      - UIE_ENABLED=0：直接返回空，完全跳过
      - 模型不可用：返回空
      - 否则按 UIE_MAX_CHUNK 分块推理，受 AI 信号量保护
    """
    if not UIE_ENABLED:
        return []
    uie = get_uie_engine()
    if uie is None:
        return []

    results = []
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


def _post_filter(findings: list, text: str, field_name: str = None) -> list:
    """
    过滤非结构化文本的 FP。统一在这里做，覆盖所有上游路径：
      - [P0-A] 字段黑名单：CHINESE_NAME 跳过
      - [P0-B] 职务/称谓后缀：CHINESE_NAME 跳过
      - IP_ADDRESS 剔除紧跟 /数字 或 :数字 的版本/端口/CIDR
      - EMAIL 剔除无合法 TLD 的
    """
    result = []
    field_blacklisted = bool(field_name) and is_name_fp_field(field_name)
    for f in findings:
        stype = f.get("sensitive_type")
        val = f.get("extracted_value", "")

        if stype == "CHINESE_NAME":
            # [P0-A] 字段在 FP 黑名单 → 所有中文名全部丢
            if field_blacklisted:
                continue
            # [P0-B] 称谓型名字（兜底 UIE 可能返回的"王审计员"；虽然 schema 已裁剪，
            #        但保留此检查防其它路径漏网）
            if is_job_title_name(val):
                continue

        if stype == "IP_ADDRESS":
             idx = text.find(val)
             if idx >= 0:
                 after = text[idx + len(val):idx + len(val) + 4]
                 # 过滤 CIDR(/24 等)
                 if _IP_CIDR_SUFFIX.match(after):
                     continue
                 # 过滤版本号(1.2.3.4.5 截出的假 IP)
                 if _IP_VERSION_SUFFIX.match(after):
                     continue
                 # 不再过滤 :端口 —— "192.168.1.1:8080" 里的 IP 是合法答案
        elif stype == "EMAIL":
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

    # 1) 正则扫描（姓名/地址走专项逻辑）
    for stype, val in extract_sensitive_from_value(value_str):
        if stype not in ("CHINESE_NAME", "ADDRESS"):
            _add(stype, val)

    # 2) 中文姓名（姓氏词典 + 黑名单 + P0-B/P0-D 过滤）
    for stype, val in _scan_chinese_names(value_str):
        _add(stype, val)

    # 3) 地址
    for stype, val in _scan_addresses(value_str):
        _add(stype, val)

    # 4) UIE NER —— 审计模式下不合并，只打日志
    uie_raw = _run_uie(value_str)
    if uie_raw:
        if UIE_AUDIT:
            regex_keys = {(f["sensitive_type"], f["extracted_value"]) for f in findings}
            for stype, val in uie_raw:
                in_regex = (stype, val) in regex_keys
                _uie_logger.warning(
                    "UIE_DIFF table=%s field=%s id=%s type=%s val=%r in_regex=%s",
                    table_name, field_col_name, record_id, stype, val, in_regex,
                )
        else:
            for stype, val in uie_raw:
                _add(stype, val)

    findings = _post_filter(findings, value_str, field_name=field_name)
    return findings
