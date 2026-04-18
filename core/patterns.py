import re
from core.config import MAX_SCAN_LEN

COMMON_SURNAMES = [
    # 百家姓常见单字姓
    "李", "王", "张", "刘", "陈", "杨", "赵", "黄", "周", "吴",
    "徐", "孙", "胡", "朱", "高", "林", "何", "郭", "马", "罗",
    "梁", "宋", "郑", "谢", "韩", "唐", "冯", "于", "董", "萧",
    "程", "曹", "袁", "邓", "许", "傅", "沈", "曾", "彭", "吕",
    "苏", "卢", "蒋", "蔡", "贾", "丁", "魏", "薛", "叶", "阎",
    "余", "潘", "杜", "戴", "夏", "锺", "汪", "田", "任", "姜",
    "范", "方", "石", "姚", "谭", "廖", "邹", "熊", "金", "陆",
    "郝", "孔", "白", "崔", "康", "毛", "邱", "秦", "江", "史",
    "顾", "侯", "邵", "孟", "龙", "万", "段", "钱", "汤", "窦",
    "尹", "黎", "易", "常", "武", "乔", "贺", "赖", "龚", "文",
    # example.csv 中出现的额外姓氏（单字）
    "公", "吉", "乐", "鄂", "家", "伶", "贡", "苍", "晏", "华",
    "郁", "桂", "崎", "禄", "阚", "羿", "汲", "信", "边", "仲",
    "共", "暨", "巢", "翟", "蔚", "步", "厉", "空", "隗", "牧",
    "富", "靳", "殷", "终", "明", "同", "元", "令", "东", "即",
    "越", "浦", "向", "臧", "贝", "乜", "亓", "籍", "漕", "花",
    "赫", "霍", "欧", "游", "苗", "古", "储", "聂", "阮", "莫",
    "帅", "焦", "巴", "干", "甘", "连", "解", "屈", "晁", "柴",
    "冷", "汝", "兰", "温", "司", "包", "蒲", "居",
    # example.csv 漏报姓氏补充
    "陶", "蒙", "郜", "湛", "宁", "伏", "谈", "沃", "雷", "胥", "尚",
]

# 模块级预编译，避免热路径重建（fix P1）
_SURNAMES_SET = frozenset(COMMON_SURNAMES)

# 复姓（双字姓）列表，用于辅助识别4字名
COMPOUND_SURNAMES = {
    "仲孙", "公冶", "公良", "公羊", "公孙", "令狐", "共叔", "即墨",
    "东方", "东乡", "西门", "南宫", "北宫", "上官", "夏侯", "诸葛",
    "司马", "司徒", "司空", "欧阳", "左丘", "太史", "端木", "轩辕",
    "皇甫", "呼延", "慕容", "宇文", "长孙", "尉迟", "独孤", "拓跋",
    "元亓", "同蹄", "伶舟", "公叔", "乐正", "万俟", "赫连",
}

NAME_BLACKLIST = {
    "系统", "管理员", "用户", "客户", "测试", "操作员", "访客", "匿名",
    "超级", "普通", "默认", "临时", "公司", "企业", "机构", "部门",
    "服务", "平台", "应用", "接口", "数据", "信息", "记录", "账号",
}

# [P4] 预编译黑名单正则，替换 O(n) 子串循环
_NAME_BLACKLIST_RE = re.compile("|".join(re.escape(w) for w in NAME_BLACKLIST))

FIELD_NAME_DICT = {
    "CHINESE_NAME": [
        r"\breal_name\b", r"\btrue_name\b", r"\bcustomer_name\b", r"\buser_name\b",
        r"\bfull_name\b", r"\bperson_name\b", r"\bclient_name\b", r"\bowner_name\b",
        r"\bcontact_name\b", r"\bapplicant_name\b", r"\bxingming\b", r"\bxm\b",
        r"\bname\b",
    ],
    "PHONE_NUMBER": [
        r"\bphone\b", r"\bmobile\b", r"\btel\b", r"\bcellphone\b",
        r"\bphone_number\b", r"\bmobile_number\b", r"\bcontact_phone\b",
        r"\bphone_no\b", r"\btel_no\b", r"\bshouji\b",
    ],
    "EMAIL": [
        r"\bemail\b", r"\be_mail\b", r"\bemail_address\b", r"\bmail\b",
        r"\bcontact_email\b", r"\buser_email\b",
    ],
    "ADDRESS": [
        r"\baddress\b", r"\bhome_address\b", r"\bresidence\b", r"\blocation\b",
        r"\baddr\b", r"\bstreet\b", r"\bdizhi\b",
    ],
    "ID_CARD": [
        r"\bid_card\b", r"\bid_no\b", r"\bidentity_card\b", r"\bidcard\b",
        r"\bid_number\b", r"\bsfz\b", r"\bshenfenzheng\b", r"\bnational_id\b",
    ],
    "BANK_CARD": [
        r"\bbank_card\b", r"\bcard_no\b", r"\bbank_account\b", r"\baccount_no\b",
        r"\bcard_number\b", r"\bbankcard\b", r"\byinhangka\b",
    ],
    "PASSPORT": [
        r"\bpassport\b", r"\bpassport_no\b", r"\bpassport_number\b", r"\bhuzhao\b",
    ],
    "MILITARY_ID": [
        r"\bmilitary_id\b", r"\bjunguanzheng\b", r"\bmilitary_no\b",
    ],
    "LICENSE_PLATE": [
        r"\bplate\b", r"\blicense_plate\b", r"\bcar_plate\b", r"\bvehicle_plate\b",
        r"\bchepai\b", r"\bplate_no\b",
    ],
    "VIN_CODE": [
        r"\bvin\b", r"\bvin_code\b", r"\bvehicle_id\b", r"\bchassis_no\b",
    ],
    "IP_ADDRESS": [
        r"\bip\b", r"\bip_address\b", r"\bclient_ip\b", r"\bremote_ip\b",
        r"\bserver_ip\b", r"\bsource_ip\b",
    ],
    "MAC_ADDRESS": [
        r"\bmac\b", r"\bmac_address\b", r"\bdevice_mac\b", r"\bhardware_addr\b",
    ],
    "GPS_COORDINATE": [
        r"\bgps\b", r"\blatitude\b", r"\blongitude\b",
        r"\blat\b", r"\blng\b", r"\bcoordinate\b", r"\bjingwei\b",
    ],
    "USCC": [
        r"\buscc\b", r"\bcredit_code\b", r"\bunified_code\b", r"\bsocial_credit\b",
        r"\bshehui_xinyong\b",
    ],
    "BUSINESS_LICENSE_NO": [
        r"\bbusiness_license\b", r"\blicense_no\b", r"\byingye_zhizhao\b",
        r"\bregistration_no\b",
    ],
    "SOCIAL_SECURITY_NO": [
        r"\bsocial_security\b", r"\bss_no\b", r"\bshebao\b", r"\binsurance_no\b",
    ],
    "HOUSING_FUND_NO": [
        r"\bhousing_fund\b", r"\bgongjijin\b", r"\bprovident_fund\b",
    ],
    "MEDICAL_INSURANCE_NO": [
        r"\bmedical_insurance\b", r"\byibao\b", r"\bhealth_insurance\b",
    ],
    "MEDICAL_RECORD_NO": [
        r"\bmedical_record\b", r"\bpatient_id\b", r"\bcase_no\b", r"\bbingli\b",
    ],
    "PASSWORD_OR_SECRET": [
        r"\bpassword\b", r"\bpasswd\b", r"\bpwd\b", r"\bsecret\b",
        r"\btoken\b", r"\bapi_key\b", r"\bapikey\b", r"\bprivate_key\b",
        r"\bsecret_key\b", r"\baccess_token\b", r"\bauth_token\b",
        r"\brefresh_token\b", r"\bcredential\b",
    ],
}

_FIELD_NAME_COMPILED = {
    stype: [re.compile(p, re.IGNORECASE) for p in patterns]
    for stype, patterns in FIELD_NAME_DICT.items()
}

REGEX_PATTERNS = {
    "PHONE_NUMBER": re.compile(
        r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)"
    ),
    "EMAIL": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    ),
    "ID_CARD": re.compile(
        r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"
    ),
    "BANK_CARD": re.compile(
        r"(?<!\d)[3-9]\d{15,18}(?!\d)"
    ),
    "PASSPORT": re.compile(
        r"(?<![A-Z0-9])[EGDPS]\d{8}(?![A-Z0-9])"  # [修改] 添加了 P 和 S 护照类型，防止漏报
    ),
    # [修复] 匹配海字第、空字第、南字第等所有兵种军区前缀，防止漏报
    "MILITARY_ID": re.compile(
        r"[\u4e00-\u9fa5]{1,2}字第\s*\d{4,8}\s*号"
    ),
    "IP_ADDRESS": re.compile(
        r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"
    ),
    "MAC_ADDRESS": re.compile(
        r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}"
    ),
    "GPS_COORDINATE": re.compile(
        r"-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}"
    ),
    # [修复] 新能源车牌可能有6位数字，并且可能包含中间的点
    "LICENSE_PLATE": re.compile(
        r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁夏]"
        r"[A-Z][·•]?[A-Z0-9]{4,6}(?!\d)"
    ),
    # [修复] 强制要求17位字符中必须包含至少一个字母，防止把17位纯数字的银行卡误判为车架号
    "VIN_CODE": re.compile(
        r"(?<![A-HJ-NPR-Z0-9])(?=.*[A-HJ-NPR-Z])[A-HJ-NPR-Z0-9]{17}(?![A-HJ-NPR-Z0-9])"
    ),
    # 统一社会信用代码：第1位登记管理部门(1-9/A-N/P-Y) + 第2位机构类别(1-9/A-Z) + 6位行政区划 + 9位组织机构 + 1位校验
    "USCC": re.compile(
        r"(?<![A-Z0-9])[0-9A-NP-Y][0-9A-Z]\d{6}[0-9A-Z]{9}[0-9A-Z](?![A-Z0-9])"
    ),
    # [修改] 营业执照 15 位纯数字无结构特征，主扫逻辑中不再盲扫，
    #        改为仅在字段名命中 BUSINESS_LICENSE_NO 时由 extract_by_field_hint 显式调用。
    "BUSINESS_LICENSE_NO": re.compile(
        r"(?<!\d)[1-9]\d{14}(?!\d)"
    ),
    # 社保号：省份汉字 + 2大写字母 + 8位数字，共11位
    "SOCIAL_SECURITY_NO": re.compile(
        r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁夏][A-Z]{2}\d{8}"
    ),
    # 住房公积金：2位城市代码 + 11位数字，共13位
    "HOUSING_FUND_NO": re.compile(
        r"(?<![A-Z])[A-Z]{2}20[12]\d{8}(?!\d)"
    ),
    # 医保卡号：YB + 14-16位数字
    "MEDICAL_INSURANCE_NO": re.compile(
        r"YB\d{14,16}"
    ),
    # 病历号：MR + 9位数字，共11位
    "MEDICAL_RECORD_NO": re.compile(
        r"MR\d{9}"
    ),
    "CHINESE_NAME": re.compile(
        r"[\u4e00-\u9fa5]{2,4}"
    ),
    # [修复] 限制省市区前缀的汉字长度，防止在长文本中向前贪婪吞噬无关文字导致大规模误报
    "ADDRESS": re.compile(
        r"(?:(?:[\u4e00-\u9fa5]{2,4}省|[\u4e00-\u9fa5]{2,5}自治区)\s*)?"
        r"(?:[\u4e00-\u9fa5]{2,6}市\s*)?"
        r"(?:[\u4e00-\u9fa5]{2,6}[区县]\s*)?"
        r"[\u4e00-\u9fa5a-zA-Z\d\-]{2,30}(?:街道|路|街|号|栋|室|弄|巷|村|组)"
    ),
}

# ── 密码/密钥专项正则 ──────────────────────────────────────────────
# [改进] 拆分成独立正则，逻辑清晰，每种类型自带提取策略
_BCRYPT_RE = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")
_SK_KEY_RE = re.compile(r"sk-[A-Za-z0-9]{20,}")
_AK_KEY_RE = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")  # AWS Access Key
# MD5 / SHA-1 / SHA-256 哈希（32 / 40 / 64 位 hex，两端不能紧邻 hex 字符）
_HASH_RE = re.compile(
    r"(?<![a-fA-F0-9])"
    r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})"
    r"(?![a-fA-F0-9])"
)
# 键值对（支持带引号和不带引号）：password = 'xxx' / password:"xxx" / password=xxx
_PWD_KV_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|"
    r"access[_-]?token|auth[_-]?token|refresh[_-]?token|credential)"
    r"\s*[:=]\s*"
    r"(?:[\"']([^\"'\n\r]{4,200})[\"']|([A-Za-z0-9_@#$%^&*\-!.+/=]{6,200}))",
    re.IGNORECASE,
)

_ID_CARD_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CARD_CHECK = "10X98765432"


def validate_id_card(id_str: str) -> bool:
    id_str = id_str.upper().strip()
    if len(id_str) != 18:
        return False
    if not id_str[:17].isdigit():
        return False
    total = sum(int(id_str[i]) * _ID_CARD_WEIGHTS[i] for i in range(17))
    return _ID_CARD_CHECK[total % 11] == id_str[17]


def validate_luhn(card_str: str) -> bool:
    digits = [int(c) for c in card_str if c.isdigit()]
    if len(digits) < 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def validate_uscc(uscc_str: str) -> bool:
    if len(uscc_str) != 18:
        return False
    valid_chars = set("0123456789ABCDEFGHJKLMNPQRTUWXY")
    return all(c in valid_chars for c in uscc_str)


def validate_business_license(val: str) -> bool:
    """
    15 位营业执照号校验：
      - 全数字
      - 第 1 位非 0
      - 第 3-6 位（行政区划代码后 4 位）不全为 0
    """
    if len(val) != 15 or not val.isdigit():
        return False
    if val[0] == "0":
        return False
    if int(val[2:6]) == 0:
        return False
    return True


def match_field_name(field_name: str) -> list:
    matched = []
    for stype, patterns in _FIELD_NAME_COMPILED.items():
        for p in patterns:
            if p.search(field_name):
                matched.append(stype)
                break
    return matched


def _extract_password_candidates(value_str: str) -> list:
    """
    从字符串里提取各类密码/密钥候选值。
    返回 [(sensitive_type, extracted_value), ...]
    """
    results = []
    seen = set()

    def _add(val):
        if val and val not in seen:
            seen.add(val)
            results.append(("PASSWORD_OR_SECRET", val))

    # bcrypt 哈希 —— 整串即为敏感值
    for m in _BCRYPT_RE.finditer(value_str):
        _add(m.group())

    # OpenAI 类 sk- 密钥
    for m in _SK_KEY_RE.finditer(value_str):
        _add(m.group())

    # AWS Access Key
    for m in _AK_KEY_RE.finditer(value_str):
        _add(m.group())

    # MD5 / SHA 哈希
    for m in _HASH_RE.finditer(value_str):
        _add(m.group())

    # k=v 形式
    for m in _PWD_KV_RE.finditer(value_str):
        # group(1) 是带引号匹配，group(2) 是不带引号匹配
        val = m.group(1) if m.group(1) is not None else m.group(2)
        if val:
            _add(val.strip())

    return results


def extract_sensitive_from_value(value_str: str) -> list:
    if not value_str or not isinstance(value_str, str):
        return []

    # [性能 #12] 超长输入截断：50KB 文本跑 20+ 正则在纯 Python 下可能到几百毫秒
    # 一张含长日志的大表能因此拖垮整个时间预算
    if len(value_str) > MAX_SCAN_LEN:
        value_str = value_str[:MAX_SCAN_LEN]

    results = []
    seen = set()  # 去重：同一 (stype, val) 只输出一次
    found_id_card_spans = []
    found_uscc_spans = []

    def _add(stype, val):
        key = (stype, val)
        if key not in seen:
            seen.add(key)
            results.append((stype, val))

    for m in REGEX_PATTERNS["ID_CARD"].finditer(value_str):
        if validate_id_card(m.group()):
            _add("ID_CARD", m.group())
            found_id_card_spans.append((m.start(), m.end()))

    for m in REGEX_PATTERNS["USCC"].finditer(value_str):
        overlap = any(s <= m.start() < e or s < m.end() <= e
                      for s, e in found_id_card_spans)
        if not overlap and validate_uscc(m.group()):
            _add("USCC", m.group())
            found_uscc_spans.append((m.start(), m.end()))

    for m in REGEX_PATTERNS["BANK_CARD"].finditer(value_str):
        overlap = any(s <= m.start() < e or s < m.end() <= e
                      for s, e in found_id_card_spans + found_uscc_spans)
        if not overlap and validate_luhn(m.group()):
            _add("BANK_CARD", m.group())

    # [改进] 密码/密钥专项提取，拆分成独立正则，更清晰
    for stype, val in _extract_password_candidates(value_str):
        _add(stype, val)

    # [修改] skip_types 追加 BUSINESS_LICENSE_NO —— 盲扫会产生海量 FP，
    #        该类型只能在字段名命中时通过 extract_by_field_hint 调用
    skip_types = {
        "ID_CARD", "USCC", "BANK_CARD",
        "CHINESE_NAME", "ADDRESS",
        "BUSINESS_LICENSE_NO",
    }
    for stype, pattern in REGEX_PATTERNS.items():
        if stype in skip_types:
            continue
        for m in pattern.finditer(value_str):
            _add(stype, m.group())

    # 使用模块级预编译的 frozenset（fix P1）
    for m in REGEX_PATTERNS["CHINESE_NAME"].finditer(value_str):
        name = m.group()
        if _NAME_BLACKLIST_RE.search(name):
            continue
        if name[0] in _SURNAMES_SET:
            _add("CHINESE_NAME", name)
            continue
        if len(name) >= 3 and name[:2] in COMPOUND_SURNAMES:
            _add("CHINESE_NAME", name)

    for m in REGEX_PATTERNS["ADDRESS"].finditer(value_str):
        if len(m.group()) >= 10:
            _add("ADDRESS", m.group())

    return results


def extract_by_field_hint(field_name: str, value_str: str) -> list:
    """
    [新增] 当字段名明确提示敏感类型时，显式触发那些在盲扫中被跳过的正则。
    目前只用于 BUSINESS_LICENSE_NO —— 15 位纯数字只有在字段名提示下才识别。

    调用方：scan_structured_field 在默认分支补调一次这个函数。
    """
    hits = []
    if not value_str or not isinstance(value_str, str):
        return hits

    field_types = match_field_name(field_name)
    if not field_types:
        return hits

    if "BUSINESS_LICENSE_NO" in field_types:
        for m in REGEX_PATTERNS["BUSINESS_LICENSE_NO"].finditer(value_str):
            val = m.group()
            # 排除与银行卡冲突（通过 Luhn 则按银行卡处理）
            if validate_luhn(val):
                continue
            # 排除 18 位 USCC/ID_CARD 的子串（避免重叠）
            if REGEX_PATTERNS["USCC"].fullmatch(val):
                continue
            if not validate_business_license(val):
                continue
            hits.append(("BUSINESS_LICENSE_NO", val))

    return hits
