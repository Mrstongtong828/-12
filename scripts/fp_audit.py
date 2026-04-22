# -*- coding: utf-8 -*-
"""FP 审计脚本：upload.csv 自查重复/放大/噪声"""
import csv
import sys
from collections import Counter, defaultdict

UPLOAD = r"E:\数据库敏感字段识别与安全管控系统\项目\output\upload(5).csv"
EXAMPLE = r"E:\数据库敏感字段识别与安全管控系统\项目\output\example(6).csv"


def load(path):
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def main():
    up = load(UPLOAD)
    ex = load(EXAMPLE)
    print(f"upload 行数: {len(up)}")
    print(f"example 行数: {len(ex)}")
    print()

    # 1. 7 元组重复
    key7 = lambda r: (
        r["db_type"], r["db_name"], r["table_name"], r["field_name"],
        r["record_id"], r["sensitive_type"], r["extracted_value"]
    )
    c7 = Counter(key7(r) for r in up)
    dup7 = {k: v for k, v in c7.items() if v > 1}
    print(f"=== 1. 7 元组重复 ===")
    print(f"重复 7 元组唯一键数: {len(dup7)}")
    print(f"重复引入的冗余行数: {sum(v - 1 for v in dup7.values())}")
    if dup7:
        print("Top 10 重复键 (key → 重复次数):")
        for k, v in sorted(dup7.items(), key=lambda x: -x[1])[:10]:
            print(f"  x{v}  {k}")
    print()

    # 2. 按 data_form 放大倍数
    print(f"=== 2. data_form 放大倍数 ===")
    up_form = Counter(r["data_form"] for r in up)
    ex_form = Counter(r["data_form"] for r in ex)
    print(f"{'form':<20}{'upload':>10}{'example':>10}{'放大':>10}")
    for form in set(up_form) | set(ex_form):
        u, e = up_form.get(form, 0), ex_form.get(form, 0)
        ratio = f"{u/e:.1f}x" if e else "∞"
        print(f"{form:<20}{u:>10}{e:>10}{ratio:>10}")
    print()

    # 3. 按 sensitive_type 放大
    print(f"=== 3. sensitive_type 放大倍数 ===")
    up_t = Counter(r["sensitive_type"] for r in up)
    ex_t = Counter(r["sensitive_type"] for r in ex)
    rows = []
    for t in set(up_t) | set(ex_t):
        u, e = up_t.get(t, 0), ex_t.get(t, 0)
        ratio = u / e if e else float("inf")
        rows.append((t, u, e, ratio))
    rows.sort(key=lambda x: -x[3] if x[3] != float("inf") else -1e9)
    print(f"{'type':<25}{'upload':>8}{'example':>8}{'放大':>10}")
    for t, u, e, r in rows:
        rs = f"{r:.1f}x" if r != float("inf") else "∞"
        print(f"{t:<25}{u:>8}{e:>8}{rs:>10}")
    print()

    # 4. 按 (db_name, table_name, field_name) 找热点
    print(f"=== 4. 顶级热点字段 (upload 行数 Top 15) ===")
    field_cnt = Counter((r["db_name"], r["table_name"], r["field_name"], r["data_form"]) for r in up)
    for k, v in field_cnt.most_common(15):
        print(f"  {v:>6}  {k}")
    print()

    # 5. 噪声检测：N/A_ 占位符 / extracted_value 过短或过长
    print(f"=== 5. 可疑值模式 ===")
    na_pattern = sum(1 for r in up if r["extracted_value"].startswith("N/A_"))
    empty = sum(1 for r in up if not r["extracted_value"].strip())
    too_short = sum(1 for r in up if len(r["extracted_value"]) < 2)
    placeholder = sum(1 for r in up if r["extracted_value"] in ("None", "null", "NULL", "[FIELD_NAME_HINT]"))
    print(f"  N/A_*** 前缀: {na_pattern}")
    print(f"  空值/全空格: {empty}")
    print(f"  长度<2: {too_short}")
    print(f"  占位符 (None/null/...): {placeholder}")
    print()

    # 6. 同 (table, field, record_id) 但 extracted_value 多次写入(多值正常, 但统计异常值)
    print(f"=== 6. 同一记录提取值数 ===")
    per_record = defaultdict(list)
    for r in up:
        k = (r["db_name"], r["table_name"], r["field_name"], r["record_id"])
        per_record[k].append(r["extracted_value"])
    distro = Counter(len(set(v)) for v in per_record.values())
    print("同一 record 提取唯一值数 → 记录数:")
    for n in sorted(distro):
        print(f"  {n} 个唯一值: {distro[n]} 条记录")


if __name__ == "__main__":
    main()
