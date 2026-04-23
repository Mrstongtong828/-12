"""
脱敏工具集。

设计原则(对齐赛题 (3)-5):
  - 针对不同数据形态和敏感类型设计合理脱敏方案
  - 保留数据可用性(部分位可见)或完全不可逆(密码类)
  - 支持批量处理 upload.csv,生成脱敏前后对比

用法:
    from core.masking import mask_value, batch_mask_csv

    # 单值脱敏
    masked = mask_value("PHONE_NUMBER", "13812345678")
    # → "138****5678"

    # 批量处理(用于研究报告对比展示)
    batch_mask_csv("output/upload.csv", "output/masked.csv")
"""
import csv
import hashlib
import re


# ═══════════════════════════════════════════════════════════════
# 脱敏策略映射(赛题 sensitive_type → 脱敏方法)
# ═══════════════════════════════════════════════════════════════
#
# 设计原则:
#   - L4(核心隐私) → 强脱敏(大部分位隐藏 或 哈希)
#   - L3(个人信息) → 部分脱敏(保留前后少量位)
#   - L2(设备标识) → 轻度脱敏(保留网段/厂商)
#
# 各字段脱敏策略:
#   PHONE_NUMBER         保留前3后4   13812345678   → 138****5678
#   ID_CARD              保留前6后4   44010619900101xxxx → 440106********1234
#   BANK_CARD            保留前4后4   6222021234567890123 → 6222***********0123
#   CHINESE_NAME         保留姓氏     张三          → 张*
#                                    仲孙歌阑      → 仲孙**
#   EMAIL                部分保留     alice@qq.com  → a****@qq.com
#   ADDRESS              保留省市     广东省广州市...  → 广东省广州市****
#   PASSPORT             保留首字母+后2位             → E******78
#   PASSWORD_OR_SECRET   SHA-256 全哈希              → [SHA256:abcdef...]
#   IP_ADDRESS           保留前两段   192.168.1.100 → 192.168.*.*
#   MAC_ADDRESS          保留厂商OUI  76:c9:f9:d3:e1:c5 → 76:c9:f9:**:**:**
#   GPS_COORDINATE       保留整数位   23.1291,113.2644 → 23.*,113.*
#   LICENSE_PLATE        保留省份+首位 粤A12345     → 粤A*****
#   MEDICAL_RECORD_NO    保留MR前缀+年份 MR202400001 → MR2024*****
#   MEDICAL_INSURANCE_NO 保留前4位    YB44010620240001 → YB44************
#   SOCIAL_SECURITY_NO   保留省份+字母 粤SB20240001 → 粤SB********
#   HOUSING_FUND_NO      保留前2位    GZ20240001234 → GZ***********
#   VIN_CODE             保留前3后4   LSVAU2180N2123456 → LSV**********3456
#   USCC                 保留前8后4   91440101MA5EXAMPLE123 → 91440101********MPLE
#   BUSINESS_LICENSE_NO  保留前6位    440106000123456 → 440106*********
#   MILITARY_ID          全遮蔽                      → [MILITARY_REDACTED]


def _mask_middle(value: str, keep_front: int, keep_back: int,
                 mask_char: str = "*") -> str:
    """通用掩码:保留前 N + 后 M 位,中间用 * 代替。"""
    if not value:
        return value
    v = str(value)
    if len(v) <= keep_front + keep_back:
        # 太短就保留首位 + 全遮后面
        if len(v) <= 2:
            return v[0] + mask_char * (len(v) - 1) if v else v
        return v[0] + mask_char * (len(v) - 1)
    middle_len = len(v) - keep_front - keep_back
    return v[:keep_front] + mask_char * middle_len + v[-keep_back:] if keep_back > 0 \
        else v[:keep_front] + mask_char * middle_len


def mask_phone(v):
    return _mask_middle(v, 3, 4)


def mask_id_card(v):
    return _mask_middle(v, 6, 4)


def mask_bank_card(v):
    return _mask_middle(v, 4, 4)


def mask_email(v):
    if not v or "@" not in v:
        return v
    local, domain = v.split("@", 1)
    if len(local) <= 1:
        return v
    return local[0] + "*" * max(1, len(local) - 1) + "@" + domain


def mask_chinese_name(v):
    """保留姓氏(单姓 1 字 / 复姓 2 字),其余遮蔽。"""
    if not v:
        return v
    # 复姓判断(简单启发式:前2字是已知复姓则保留2字,否则保留1字)
    COMPOUND = {"仲孙", "公冶", "公良", "公羊", "公孙", "令狐", "即墨",
                "东方", "东乡", "西门", "南宫", "北宫", "上官", "夏侯", "诸葛",
                "司马", "司徒", "司空", "欧阳", "左丘", "太史", "端木", "轩辕",
                "皇甫", "呼延", "慕容", "宇文", "长孙", "尉迟", "独孤", "拓跋",
                "公甲", "公荆", "伶舟", "元亓", "赫连"}
    if len(v) >= 4 and v[:2] in COMPOUND:
        return v[:2] + "*" * (len(v) - 2)
    if len(v) >= 2:
        return v[0] + "*" * (len(v) - 1)
    return v


def mask_address(v):
    """保留省+市,其余遮蔽。"""
    if not v:
        return v
    # 定位市后位置
    for keyword in ["市", "自治州", "地区"]:
        idx = v.find(keyword)
        if idx > 0 and idx < len(v) - 1:
            return v[:idx + len(keyword)] + "*" * (len(v) - idx - len(keyword))
    # 没找到市就保留省
    idx = v.find("省")
    if idx > 0:
        return v[:idx + 1] + "*" * (len(v) - idx - 1)
    return _mask_middle(v, 3, 0)


def mask_ip(v):
    """保留前两段,后两段遮蔽。192.168.1.100 → 192.168.*.*"""
    if not v:
        return v
    parts = v.split(".")
    if len(parts) != 4:
        return v
    return f"{parts[0]}.{parts[1]}.*.*"


def mask_mac(v):
    """保留前 3 组(厂商 OUI),后 3 组遮蔽。"""
    if not v:
        return v
    parts = re.split(r"[:\-]", v)
    if len(parts) != 6:
        return v
    sep = ":" if ":" in v else "-"
    return sep.join(parts[:3]) + sep + sep.join(["**"] * 3)


def mask_gps(v):
    """经纬度保留整数位,小数部分遮蔽。23.1291,113.2644 → 23.*,113.*"""
    if not v:
        return v
    def _mask_coord(s):
        s = s.strip()
        if "." in s:
            return s.split(".")[0] + ".*"
        return s
    if "," in v:
        parts = [p.strip() for p in v.split(",")]
        return ", ".join(_mask_coord(p) for p in parts)
    return v


def mask_license_plate(v):
    """保留省份+首字母,余遮蔽。粤A12345 → 粤A*****"""
    if not v or len(v) < 2:
        return v
    return v[:2] + "*" * (len(v) - 2)


def mask_passport(v):
    """保留首字母 + 后 2 位。E12345678 → E******78"""
    return _mask_middle(v, 1, 2)


def mask_medical_record(v):
    """MR+年份保留,序号遮蔽。MR202400001 → MR2024*****"""
    if not v or not v.startswith("MR"):
        return _mask_middle(v, 2, 0)
    return v[:6] + "*" * (len(v) - 6)


def mask_medical_insurance(v):
    """保留 YB + 前 2 位省份代码,余遮蔽。"""
    return _mask_middle(v, 4, 0)


def mask_social_security(v):
    """保留省份汉字 + 2 字母,数字遮蔽。"""
    return _mask_middle(v, 3, 0)


def mask_housing_fund(v):
    """保留前 2 位城市代码。"""
    return _mask_middle(v, 2, 0)


def mask_vin(v):
    """保留 WMI(前 3 位) + 序列号末 4 位。"""
    return _mask_middle(v, 3, 4)


def mask_uscc(v):
    """保留登记管理部门(1) + 机构类别(1) + 行政区划(6) + 末 4 位。"""
    return _mask_middle(v, 8, 4)


def mask_business_license(v):
    """保留行政区划(6 位)。"""
    return _mask_middle(v, 6, 0)


def mask_military(v):
    """军官证全遮蔽(涉密等级高)。"""
    return "[MILITARY_REDACTED]"


def hash_secret(v):
    """密码/密钥 → SHA-256 单向哈希(不可逆)。"""
    if not v:
        return v
    h = hashlib.sha256(str(v).encode("utf-8")).hexdigest()
    return f"[SHA256:{h[:16]}...]"


# ═══════════════════════════════════════════════════════════════
# 主调度
# ═══════════════════════════════════════════════════════════════

MASK_STRATEGY = {
    "PHONE_NUMBER":         mask_phone,
    "ID_CARD":              mask_id_card,
    "BANK_CARD":            mask_bank_card,
    "EMAIL":                mask_email,
    "CHINESE_NAME":         mask_chinese_name,
    "ADDRESS":              mask_address,
    "IP_ADDRESS":           mask_ip,
    "MAC_ADDRESS":          mask_mac,
    "GPS_COORDINATE":       mask_gps,
    "LICENSE_PLATE":        mask_license_plate,
    "PASSPORT":             mask_passport,
    "MEDICAL_RECORD_NO":    mask_medical_record,
    "MEDICAL_INSURANCE_NO": mask_medical_insurance,
    "SOCIAL_SECURITY_NO":   mask_social_security,
    "HOUSING_FUND_NO":      mask_housing_fund,
    "VIN_CODE":             mask_vin,
    "USCC":                 mask_uscc,
    "BUSINESS_LICENSE_NO":  mask_business_license,
    "MILITARY_ID":          mask_military,
    "PASSWORD_OR_SECRET":   hash_secret,
}


def mask_value(sensitive_type: str, value: str) -> str:
    """
    对单个敏感值应用对应脱敏策略。未知类型保留原值。
    """
    fn = MASK_STRATEGY.get(sensitive_type)
    if fn is None:
        return value
    try:
        return fn(value)
    except Exception:
        return value


# ═══════════════════════════════════════════════════════════════
# 批量处理:读 upload.csv,生成脱敏前后对比 CSV
# ═══════════════════════════════════════════════════════════════

def batch_mask_csv(input_path: str = "output/upload.csv",
                   output_path: str = "output/masked_report.csv"):
    """
    读识别结果,对 extracted_value 应用脱敏,输出脱敏前后对比。
    用于研究报告里的"脱敏方案展示"一节。

    输出列:
      原 9 列 + masked_value(脱敏后) + mask_strategy(使用的策略名)
    """
    with open(input_path, "r", encoding="utf-8", newline="") as f_in, \
         open(output_path, "w", encoding="utf-8", newline="") as f_out:
        reader = csv.DictReader(f_in)
        out_fields = list(reader.fieldnames) + ["masked_value", "mask_strategy"]
        writer = csv.DictWriter(f_out, fieldnames=out_fields,
                                quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
        writer.writeheader()

        stats = {}
        for row in reader:
            stype = row.get("sensitive_type", "")
            val = row.get("extracted_value", "")
            masked = mask_value(stype, val)
            strategy = MASK_STRATEGY.get(stype)
            row["masked_value"] = masked
            row["mask_strategy"] = strategy.__name__ if strategy else "no_mask"
            writer.writerow(row)
            stats[stype] = stats.get(stype, 0) + 1

    print(f"[INFO] 脱敏报告已生成: {output_path}")
    print(f"[INFO] 按类型统计:")
    for stype, cnt in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"  {stype:<30} {cnt:>6}")


# ═══════════════════════════════════════════════════════════════
# CLI 入口
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        # 默认模式:批量处理
        batch_mask_csv()
    elif len(sys.argv) == 3:
        # 单值测试: python masking.py PHONE_NUMBER 13812345678
        stype, val = sys.argv[1], sys.argv[2]
        print(f"  原值: {val}")
        print(f"  脱敏: {mask_value(stype, val)}")
    else:
        print("用法:")
        print("  python -m core.masking                     # 批量处理 upload.csv")
        print("  python -m core.masking <TYPE> <VALUE>      # 单值测试")
