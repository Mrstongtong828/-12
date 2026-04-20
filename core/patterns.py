import re
from core.config import MAX_SCAN_LEN

COMMON_SURNAMES = [
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
    "公", "吉", "乐", "鄂", "家", "伶", "贡", "苍", "晏", "华",
    "郁", "桂", "崎", "禄", "阚", "羿", "汲", "信", "边", "仲",
    "共", "暨", "巢", "翟", "蔚", "步", "厉", "空", "隗", "牧",
    "富", "靳", "殷", "终", "明", "同", "元", "令", "东", "即",
    "越", "浦", "向", "臧", "贝", "乜", "亓", "籍", "漕", "花",
    "赫", "霍", "欧", "游", "苗", "古", "储", "聂", "阮", "莫",
    "帅", "焦", "巴", "干", "甘", "连", "解", "屈", "晁", "柴",
    "冷", "汝", "兰", "温", "司", "包", "蒲", "居",
    "陶", "蒙", "郜", "湛", "宁", "伏", "谈", "沃", "雷", "胥", "尚",
    "鄂", "漕", "籍", "屏",
]

_SURNAMES_SET = frozenset(COMMON_SURNAMES)

COMPOUND_SURNAMES = {
    "仲孙", "公冶", "公良", "公羊", "公孙", "令狐", "共叔", "即墨",
    "东方", "东乡", "西门", "南宫", "北宫", "上官", "夏侯", "诸葛",
    "司马", "司徒", "司空", "欧阳", "左丘", "太史", "端木", "轩辕",
    "皇甫", "呼延", "慕容", "宇文", "长孙", "尉迟", "独孤", "拓跋",
    "元亓", "同蹄", "伶舟", "公叔", "乐正", "万俟", "赫连",
    "公甲", "公荆", "公冉",
}

NAME_BLACKLIST = {
    "系统", "管理员", "用户", "客户", "测试", "操作员", "访客", "匿名",
    "超级", "普通", "默认", "临时", "公司", "企业", "机构", "部门",
    "服务", "平台", "应用", "接口", "数据", "信息", "记录", "账号",
    "家属", "签字", "总金额", "金额", "合计", "日期",
    "公金", "公学", "同总", "方签", "公朱",
    "承福", "总金", "金承",

    "万元整", "任何一方", "同协议书",
    "向对方支", "方按照本", "方收款账", "方权责如",
    "方收款", "方权责", "协议书",
    "元元微", "元元微澜",
    "梁台子",

    "蒙脱石", "蒙脱石散", "方左氧", "方阿莫",
    "方布洛", "莫西林", "莫西林胶",
    "常密度", "常密度影", "明显异", "明显异常",
    "方记", "苗氯雷", "苗氯雷他",

    "谢谢", "感谢", "多谢", "您好", "抱歉",
    "方式", "方案", "方面", "方向",
    "方账户", "方账",
    "家欺", "周协助", "高新技", "高新技术",
    "金山经", "武清汽",

    "家地址", "家地址内", "家庭地", "家庭月", "家转账", "家收款",
    "家长证", "家长证件",
    "籍地址", "籍迁移", "户籍地",
    "公民身", "民身份", "公民", "公众",
    "居民纠", "居民纠纷", "信访件", "信人殷", "信人",
    "信都高", "信都高驰",
    "东经济", "经济开",
    "蒙古武", "蒙古自", "蒙古包",

    "于验证", "于标准", "于核实",
    "即止付", "向账户", "向对方",

    "王四营",

    "方当事", "方当事人", "公输翰", "公输翰翮", "公输鹰", "公旅琛",
    "共叔傲", "共叔傲云",
}

_NAME_BLACKLIST_RE = re.compile("|".join(re.escape(w) for w in NAME_BLACKLIST))

_NAME_ADDR_CHARS = frozenset(
    "省市区县乡镇村街道路弄巷号栋楼室组院庄园区苑里"
    "局院厅局部处司委办站场库所馆组"
    "族"
)

NAME_FP_FIELD_BLACKLIST = frozenset({
    "handler", "operator", "created_by", "updated_by", "modified_by",
    "service_type", "role_name", "role", "user_role",
    "reviewer", "approver", "auditor",
    "assigned_to", "assignee", "processor",
})


def is_name_fp_field(field_name: str) -> bool:
    if not field_name:
        return False
    return field_name.lower() in NAME_FP_FIELD_BLACKLIST


NAME_JOB_SUFFIXES = (
    "警官", "警察", "干警", "法官", "检察官", "所长",
    "审计员", "专员", "经理", "主任", "科长", "处长", "部长",
    "院长", "厅长", "局长", "书记", "干部", "员工", "师傅",
    "医生", "护士", "大夫", "老师", "教授", "博士", "研究员",
    "先生", "女士", "同志",
)


def is_job_title_name(name: str) -> bool:
    if not name:
        return False
    return any(name.endswith(suf) for suf in NAME_JOB_SUFFIXES)


_NAME_VERB_CHARS = frozenset(
    "的了是在有和与及或但也把被让使"
    "炎症瘤癌疾患肿疼痛"
    "肝肺脾胃肾脑胰"
    "压住提取申办跟"
    "及等均各某"
)


def _is_verbish_name(name: str) -> bool:
    if len(name) < 2:
        return False
    return any(c in _NAME_VERB_CHARS for c in name[1:])


_NAME_TAIL_SPILLOVER = frozenset(
    "先同女老生的了吗是就都会把说想要到这那之为与和及反"
    "询账如支"
)

_NAME_TRAIL_JOB_HEADS = frozenset([
    "先生", "女士", "同志", "老师", "医生", "大夫", "警官", "先后",
])

_NAME_FOLLOW_VERB_BIGRAMS = frozenset([
    "反映", "反馈", "继续", "处理", "办理", "审查", "审核", "提交",
    "通知", "更新", "提供", "咨询", "投诉", "举报", "跟进", "欺诈",
    "告知", "询问", "拒绝", "承认", "表示", "答复", "回复", "上报",
    "解决", "配合", "确认", "申请", "申报", "退款", "退货",
    "来电", "来访", "来店", "来人", "来信",
    "报案", "报名", "报到", "报警", "报修",
    "到场", "到访", "到店",
    "取消", "取件", "取货",
    "送达", "送到",
    "入院", "入住", "入职",
    "出院", "出差",
    "离职", "离店",
    "前往", "前来",
    "希望", "要求", "请求",
    "同意", "不同",

    "身份", "身边", "身体", "身心",
    "证件", "证明", "证号", "证实", "证据",
    "民身", "民警", "民事", "民政",
    "止付", "付款", "付清", "付讫", "付给",
    "转账", "转入", "转出", "转给", "转到", "转回",
    "扣款", "扣费", "扣除",
    "退还",
    "核实", "核查", "核对", "核准", "核销",
    "验证", "验收", "验明",
    "登记", "登陆", "登录",
    "变更", "更改", "撤销",
    "家住", "家在", "家庭",
    "居住", "居民", "居所",
    "协助", "协议", "协调",
    "诉求", "控诉",
    "账户", "账号", "账单",
])


def _contains_verb_bigram(s: str) -> bool:
    return any(s[k:k+2] in _NAME_FOLLOW_VERB_BIGRAMS for k in range(len(s) - 1))


def _is_valid_name_shape(cand: str) -> bool:
    if _NAME_BLACKLIST_RE.search(cand):
        return False
    if any(c in _NAME_ADDR_CHARS for c in cand):
        return False
    if is_job_title_name(cand):
        return False
    if _is_verbish_name(cand):
        return False
    if _contains_verb_bigram(cand):
        return False
    return True


def try_name_at(text: str, i: int):
    n = len(text)
    is_compound = (i + 2 <= n and text[i:i+2] in COMPOUND_SURNAMES)
    is_single = text[i] in _SURNAMES_SET
    if not (is_compound or is_single):
        return None, 0

    # 【核心修复 1】掐断超长伪名：复姓允许 4/3/2 字，单字姓强制只能 3/2 字
    lengths = (4, 3, 2) if is_compound else (3, 2)

    for L in lengths:
        if i + L > n:
            continue
        cand = text[i:i+L]
        if not all('\u4e00' <= c <= '\u9fa5' for c in cand):
            continue
        if _contains_verb_bigram(cand):
            continue
        if L == 3 and i + L < n:
            spill_bigram = cand[-1] + text[i + L]
            if spill_bigram in _NAME_FOLLOW_VERB_BIGRAMS:
                continue
        if L == 4:
            next_char = text[i+L] if i+L < n else ''
            if cand[-1] + next_char in _NAME_TRAIL_JOB_HEADS:
                continue
            if cand[-1] + next_char in _NAME_FOLLOW_VERB_BIGRAMS:
                continue
            if cand[-1] in _NAME_TAIL_SPILLOVER:
                continue
        if i + L < n and text[i + L] in _NAME_ADDR_CHARS:
            continue
        if not _is_valid_name_shape(cand):
            continue
        return cand, L
    return None, 0


FIELD_NAME_DICT = {
    "CHINESE_NAME": [
        r"\breal_name\b", r"\btrue_name\b", r"\bcustomer_name\b", r"\buser_name\b",
        r"\bfull_name\b", r"\bperson_name\b", r"\bclient_name\b", r"\bowner_name\b",
        r"\bcontact_name\b", r"\bapplicant_name\b", r"\bconsignee\b",
        r"\bholder_name\b", r"\bpatient_name\b", r"\bxingming\b", r"\bxm\b", r"\bname\b",
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
        r"\baddr\b", r"\bstreet\b", r"\bdizhi\b", r"\bfull_address\b",
        r"\bdomicile\b", r"\bhukou\b", r"\bhuji\b",
    ],
    "ID_CARD": [
        r"\bid_card\b", r"\bid_no\b", r"\bidentity_card\b", r"\bidcard\b",
        r"\bid_number\b", r"\bsfz\b", r"\bshenfenzheng\b", r"\bnational_id\b", r"\bid_verify\b",
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
        r"\bbusiness_license\b", r"\blicense_no\b", r"\byingye_zhizhao\b", r"\bregistration_no\b",
    ],
    "SOCIAL_SECURITY_NO": [
        r"\bsocial_security\b", r"\bss_no\b", r"\bshebao\b", r"\binsurance_no\b",
    ],
    "HOUSING_FUND_NO": [
        r"\bhousing_fund\b", r"\bgongjijin\b", r"\bprovident_fund\b", r"\bhf_no\b",
    ],
    "MEDICAL_INSURANCE_NO": [
        r"\bmedical_insurance\b", r"\byibao\b", r"\bhealth_insurance\b",
    ],
    "MEDICAL_RECORD_NO": [
        r"\bmedical_record\b", r"\bpatient_id\b", r"\bcase_no\b", r"\bbingli\b", r"\bmedical_record_no\b",
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
    "PHONE_NUMBER": re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)"),
    "EMAIL": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "ID_CARD": re.compile(r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"),
    "BANK_CARD": re.compile(r"(?<!\d)[3-9]\d{14,18}(?!\d)"),
    "PASSPORT": re.compile(r"(?<![A-Z0-9])[EGDPS]\d{8}(?![A-Z0-9])"),
    "MILITARY_ID": re.compile(r"[\u4e00-\u9fa5]{1,2}字第\s*\d{4,8}\s*号"),
    "IP_ADDRESS": re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"),
    "MAC_ADDRESS": re.compile(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}"),
    "GPS_COORDINATE": re.compile(r"-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}"),
    "LICENSE_PLATE": re.compile(r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁夏][A-Z][·•]?[A-Z0-9]{4,6}(?!\d)"),
    "VIN_CODE": re.compile(r"(?<![A-HJ-NPR-Z0-9])(?=.*[A-HJ-NPR-Z])[A-HJ-NPR-Z0-9]{17}(?![A-HJ-NPR-Z0-9])"),
    "USCC": re.compile(r"(?<![A-Z0-9])[0-9A-NP-Y][0-9A-Z]\d{6}[0-9A-Z]{9}[0-9A-Z](?![A-Z0-9])"),
    "BUSINESS_LICENSE_NO": re.compile(r"(?<!\d)[1-9]\d{14}(?!\d)"),
    "SOCIAL_SECURITY_NO": re.compile(r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁夏][A-Z]{2}\d{8}"),
    "HOUSING_FUND_NO": re.compile(r"(?<![A-Z])[A-Z]{2}20[12]\d{8}(?!\d)"),
    "MEDICAL_INSURANCE_NO": re.compile(r"YB\d{14,16}"),
    "MEDICAL_RECORD_NO": re.compile(r"MR\d{9}"),
    "CHINESE_NAME": re.compile(r"[\u4e00-\u9fa5]{2,4}"),
    "ADDRESS": re.compile(
        r"(?:(?:[\u4e00-\u9fa5]{2,4}省|[\u4e00-\u9fa5]{2,5}自治区)\s*)?"
        r"(?:[\u4e00-\u9fa5]{2,6}市\s*)?"
        r"(?:[\u4e00-\u9fa5]{2,6}[区县]\s*)?"
        r"[\u4e00-\u9fa5a-zA-Z\d\-]{2,30}(?:街道|路|街|号|栋|室|弄|巷|村|组)"
    ),
}

_PSEUDO_UNICODE_TOKEN = re.compile(r"u([0-9a-fA-F]{4})")
_PSEUDO_UNICODE_MIN_TOKENS = 5

_BCRYPT_RE = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")
_SK_KEY_RE = re.compile(r"sk-[A-Za-z0-9]{20,}")
_AK_KEY_RE = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
_HASH_RE = re.compile(
    r"(?<![a-fA-F0-9])"
    r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})"
    r"(?![a-fA-F0-9])"
)
_HASH_RE_MUST_HAVE_LETTER = re.compile(r"[a-fA-F]")

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
    if not all(c in valid_chars for c in uscc_str):
        return False
    if not any(c.isalpha() for c in uscc_str):
        return False
    return True


def validate_business_license(val: str) -> bool:
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
    results = []
    seen = set()

    def _add(val):
        if val and val not in seen:
            seen.add(val)
            results.append(("PASSWORD_OR_SECRET", val))

    for m in _BCRYPT_RE.finditer(value_str):
        _add(m.group())
    for m in _SK_KEY_RE.finditer(value_str):
        _add(m.group())
    for m in _AK_KEY_RE.finditer(value_str):
        _add(m.group())
    for m in _HASH_RE.finditer(value_str):
        val = m.group()
        if not _HASH_RE_MUST_HAVE_LETTER.search(val):
            continue
        _add(val)

    for m in _PWD_KV_RE.finditer(value_str):
        val = m.group(1) if m.group(1) is not None else m.group(2)
        if val:
            _add(val.strip())

    return results


_ADDR_LABEL_PREFIXES = (
    "家庭住址", "现住址", "联系地址", "通讯地址", "户籍地址", "居住地址",
    "收货地址", "详细地址", "办公地址", "单位地址",
    "地址", "住址", "住所", "家庭地址",
    "address", "addr", "location", "home_address", "residence",
)
_ADDR_STOP_CHARS = frozenset(
    "，。；！？、：\u201c\u201d\u2018\u2019"
    ",.;:!?\"'"
    "\n\r\t"
)
_ADDR_TAIL_WORDS = (
    "号", "室", "栋", "楼", "弄", "巷", "组", "村", "院", "座", "单元",
    "街", "路", "道", "里", "苑", "区", "厂", "所", "层",
)

_ADDR_INTRO_PREFIXES = (
    "我家在", "我家住", "我现在住", "我目前住", "我住",
    "家住", "家在", "住在", "现住", "现居", "现在住",
    "位于", "地处", "坐落于", "坐落在",
    "居住于", "居住在",
    "家庭地址是", "家庭地址为", "家庭地址",
    "住址是", "住址为",
    "地址是", "地址为",
    "现住址", "家庭住址", "联系地址", "通讯地址", "户籍地址", "居住地址",
    "收货地址", "详细地址", "办公地址", "单位地址",
    "住址", "地址",
    "address:", "addr:", "location:",
    "address", "addr",
)

_ADDR_ADMIN_ANCHOR = re.compile(
    "(?:"
    "北京市|上海市|天津市|重庆市|"
    "河北省|山西省|辽宁省|吉林省|黑龙江省|江苏省|浙江省|安徽省|福建省|江西省|"
    "山东省|河南省|湖北省|湖南省|广东省|海南省|四川省|贵州省|云南省|陕西省|"
    "甘肃省|青海省|台湾省|"
    "内蒙古自治区|广西壮族自治区|西藏自治区|宁夏回族自治区|新疆维吾尔自治区|"
    "香港特别行政区|澳门特别行政区"
    ")"
)

_ADDR_ANCHOR_MAX_PREFIX = 8

_ADDR_REGION_ANCHORS = ("省", "市", "自治区", "特别行政区")


def clean_address_prefix(addr: str) -> str:
    if not addr:
        return addr
    s = addr.strip()
    original = s

    for _ in range(5):
        stripped = None
        for p in sorted(_ADDR_INTRO_PREFIXES, key=len, reverse=True):
            if s.lower().startswith(p.lower()):
                cand = s[len(p):].lstrip(" :：\t")
                if cand:
                    stripped = cand
                break
        if stripped is None:
            break
        s = stripped

    m = _ADDR_ADMIN_ANCHOR.search(s)
    if m and 0 < m.start() <= _ADDR_ANCHOR_MAX_PREFIX:
        s = s[m.start():]

    if not s or len(s) < 10:
        return original
    return s


_ADDR_ADMIN_CHARS = frozenset("省市区县")
_ADDR_STREET_CHARS = frozenset("路街巷弄号栋楼室")


def is_valid_address(val: str, strict: bool = True) -> bool:
    if not val:
        return False
    v = val.strip()

    low = v.lower()
    for p in _ADDR_LABEL_PREFIXES:
        if low.startswith(p.lower()):
            return False

    if any(c in _ADDR_STOP_CHARS for c in v):
        return False

    tail = v[-6:]
    if not any(w in tail for w in _ADDR_TAIL_WORDS):
        return False

    min_len = 15 if strict else 10
    if len(v) < min_len:
        return False
    if not any(c in _ADDR_ADMIN_CHARS for c in v):
        return False
    if not any(c in _ADDR_STREET_CHARS for c in v):
        return False
    return True


def extract_sensitive_from_value(value_str: str) -> list:
    if not value_str or not isinstance(value_str, str):
        return []

    if len(value_str) > MAX_SCAN_LEN:
        value_str = value_str[:MAX_SCAN_LEN]

    results = []
    seen = set()
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
        val = m.group()
        overlap = any(s <= m.start() < e or s < m.end() <= e
                      for s, e in found_id_card_spans + found_uscc_spans)
        if overlap:
            continue
        if validate_luhn(val):
            _add("BANK_CARD", val)
            continue
        if len(val) in (15, 16, 17, 18, 19) and val[0] in "356789":
            _add("BANK_CARD", val)

    for stype, val in _extract_password_candidates(value_str):
        _add(stype, val)

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

    i = 0
    vlen = len(value_str)
    while i < vlen:
        c = value_str[i]
        has_anchor = (c in _SURNAMES_SET
                      or (i + 2 <= vlen and value_str[i:i+2] in COMPOUND_SURNAMES))
        if has_anchor:
            name, consumed = try_name_at(value_str, i)
            if name:
                _add("CHINESE_NAME", name)
                i += consumed
                continue
        i += 1

    # 【核心修复 2】激活沉睡的盾牌：使用 is_valid_address 进行强制拦截，取代原先简陋的判断
    for m in REGEX_PATTERNS["ADDRESS"].finditer(value_str):
        addr = clean_address_prefix(m.group())
        # 利用底部的形态校验函数做兜底，过滤非地址类的长文本
        if is_valid_address(addr, strict=False):
            _add("ADDRESS", addr)

    return results


def extract_by_field_hint(field_name: str, value_str: str) -> list:
    hits = []
    if not value_str or not isinstance(value_str, str):
        return hits

    field_types = match_field_name(field_name)
    if not field_types:
        return hits

    if "BUSINESS_LICENSE_NO" in field_types:
        for m in REGEX_PATTERNS["BUSINESS_LICENSE_NO"].finditer(value_str):
            val = m.group()
            if validate_luhn(val):
                continue
            if REGEX_PATTERNS["USCC"].fullmatch(val):
                continue
            if not validate_business_license(val):
                continue
            hits.append(("BUSINESS_LICENSE_NO", val))

    return hits
