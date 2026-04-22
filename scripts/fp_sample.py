# -*- coding: utf-8 -*-
"""抽样异常放大类型的实际 extracted_value"""
import csv
import random
import sys
import io
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

UPLOAD = r"E:\数据库敏感字段识别与安全管控系统\项目\output\upload(5).csv"
EXAMPLE = r"E:\数据库敏感字段识别与安全管控系统\项目\output\example(6).csv"

def load(p):
    with open(p, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))

up = load(UPLOAD)
ex = load(EXAMPLE)

# example 里每种 sensitive_type 的真实值集合
ex_values = defaultdict(set)
for r in ex:
    ex_values[r["sensitive_type"]].add(r["extracted_value"])

# 关注这几类
targets = ["MAC_ADDRESS", "MEDICAL_INSURANCE_NO", "LICENSE_PLATE", "USCC", "ADDRESS", "CHINESE_NAME", "PASSPORT", "PASSWORD_OR_SECRET"]

random.seed(42)
for t in targets:
    rows = [r for r in up if r["sensitive_type"] == t]
    print(f"=== {t}  (upload {len(rows)} | example {len(ex_values[t])} 个唯一值) ===")
    if not rows:
        continue
    # 抽 15 个不同 extracted_value
    uniq_vals = list({r["extracted_value"] for r in rows})
    sample = random.sample(uniq_vals, min(15, len(uniq_vals)))
    for v in sample:
        hit = "Y" if v in ex_values[t] else "."
        # 找一行看上下文
        row = next(r for r in rows if r["extracted_value"] == v)
        print(f"  {hit} [{row['data_form']:<17}] {row['db_name']}.{row['table_name']}.{row['field_name']} #{row['record_id']}  → {v!r}")
    print()
