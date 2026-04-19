"""
分析官方 example.csv 的答案分布,用于指导优化方向。

用法:
    python analyze_example.py example6.csv

    或把文件放在当前目录,无参数运行:
    python analyze_example.py

输出全部打印到终端,也会写一份 analyze_example_report.txt。
复制粘贴报告内容给 Claude 就能开始针对性优化。
"""
import sys
import os
import csv
import json
from collections import Counter, defaultdict


CSV_CANDIDATES = [
    "example6.csv", "example5.csv", "example.csv",
    "docs/example.csv", "../example.csv",
]


def find_csv(argv):
    if len(argv) > 1:
        p = argv[1]
        if os.path.isfile(p):
            return p
        print(f"[ERR] 指定的文件不存在: {p}")
        sys.exit(1)
    for p in CSV_CANDIDATES:
        if os.path.isfile(p):
            return p
    print("[ERR] 没找到 example.csv。请把文件放当前目录,或命令行传路径:")
    print("      python analyze_example.py path/to/example.csv")
    sys.exit(1)


def load_rows(path):
    rows = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "db_type": (r.get("db_type") or "").strip(),
                "db_name": (r.get("db_name") or "").strip(),
                "table_name": (r.get("table_name") or "").strip(),
                "field_name": (r.get("field_name") or "").strip(),
                "record_id": (r.get("record_id") or "").strip(),
                "data_form": (r.get("data_form") or "").strip(),
                "sensitive_type": (r.get("sensitive_type") or "").strip(),
                "sensitive_level": (r.get("sensitive_level") or "").strip(),
                "extracted_value": (r.get("extracted_value") or "").strip(),
            })
    return rows


# ─────────────────────────────────────────────────────────────────

def section(title):
    line = "═" * 70
    return f"\n{line}\n  {title}\n{line}"


def fmt_counter(c, top=None):
    total = sum(c.values())
    items = c.most_common(top) if top else sorted(c.items(), key=lambda x: -x[1])
    out = []
    for k, v in items:
        pct = 100.0 * v / total if total else 0.0
        out.append(f"  {k:<35} {v:>5}  ({pct:5.1f}%)")
    out.append(f"  {'— 合计 —':<35} {total:>5}")
    return "\n".join(out)


def analyze(rows):
    buf = []
    p = buf.append

    p(section("0. 总览"))
    p(f"总行数: {len(rows)}")
    p(f"去重(七元组)后: {len(set((r['db_type'], r['db_name'], r['table_name'], r['field_name'], r['record_id'], r['sensitive_type'], r['extracted_value']) for r in rows))}")

    # ── 1. data_form 分布 ────────────────────────────────────────
    p(section("1. data_form 分布(按权重排序)"))
    FORM_WEIGHT = {
        "structured": 0.10,
        "semi_structured": 0.20,
        "encoded": 0.20,
        "unstructured_text": 0.25,
        "binary_blob": 0.20,
        "db_object": 0.05,
    }
    c_form = Counter(r["data_form"] for r in rows)
    for form in ["unstructured_text", "semi_structured", "encoded",
                 "binary_blob", "structured", "db_object"]:
        cnt = c_form.get(form, 0)
        weight = FORM_WEIGHT.get(form, 0)
        pct = 100.0 * cnt / len(rows) if rows else 0
        p(f"  {form:<22} {cnt:>5} ({pct:5.1f}%)   权重 {weight}")

    # ── 2. sensitive_type 分布 ───────────────────────────────────
    p(section("2. sensitive_type 分布"))
    c_type = Counter(r["sensitive_type"] for r in rows)
    p(fmt_counter(c_type))

    # ── 3. data_form × sensitive_type 交叉表 ────────────────────
    p(section("3. data_form × sensitive_type 交叉表(每种形态的类型分布)"))
    cross = defaultdict(Counter)
    for r in rows:
        cross[r["data_form"]][r["sensitive_type"]] += 1
    for form in sorted(cross.keys(), key=lambda f: -sum(cross[f].values())):
        total = sum(cross[form].values())
        p(f"\n  ─── {form} ({total} 行) ───")
        for stype, cnt in cross[form].most_common():
            p(f"    {stype:<30} {cnt:>4}")

    # ── 4. sensitive_level 分布(等级准确率参考) ────────────────
    p(section("4. sensitive_level 分布"))
    c_level = Counter(r["sensitive_level"] for r in rows)
    p(fmt_counter(c_level))

    # 交叉: 同一 sensitive_type 是否对应单一 level
    p(section("4b. sensitive_type → level 映射(检查等级一致性)"))
    type_to_level = defaultdict(Counter)
    for r in rows:
        type_to_level[r["sensitive_type"]][r["sensitive_level"]] += 1
    for stype in sorted(type_to_level.keys()):
        levels = type_to_level[stype]
        if len(levels) == 1:
            lvl = list(levels.keys())[0]
            p(f"  {stype:<30} → {lvl}  ({sum(levels.values())})")
        else:
            # 有多个等级,标红
            details = ", ".join(f"{l}×{c}" for l, c in levels.most_common())
            p(f"  {stype:<30} → ⚠️ 多等级: {details}")

    # ── 5. db × table 覆盖 ──────────────────────────────────────
    p(section("5. 数据库/表覆盖情况"))
    c_db = Counter((r["db_type"], r["db_name"]) for r in rows)
    p("\n  数据库分布:")
    for (dbt, dbn), cnt in c_db.most_common():
        p(f"    {dbt}/{dbn:<20} {cnt:>4}")

    c_table = Counter((r["db_name"], r["table_name"]) for r in rows)
    p(f"\n  表分布 (共 {len(c_table)} 张表):")
    for (dbn, tbl), cnt in c_table.most_common():
        p(f"    {dbn}.{tbl:<40} {cnt:>4}")

    # ── 6. field_name 频次(识别"高价值"字段) ───────────────────
    p(section("6. 高频命中的 field_name top 30"))
    c_field = Counter(r["field_name"] for r in rows)
    p(fmt_counter(c_field, top=30))

    # ── 7. 每种 data_form 抽样(用于人工看 pattern) ─────────────
    p(section("7. 每种 data_form 各抽 15 行样本"))
    seen_per_form = defaultdict(list)
    for r in rows:
        lst = seen_per_form[r["data_form"]]
        if len(lst) < 15:
            lst.append(r)
    for form, sample_list in seen_per_form.items():
        p(f"\n  ─── {form} ─── (样本 {len(sample_list)}/{c_form[form]})")
        for r in sample_list:
            val_disp = r["extracted_value"]
            if len(val_disp) > 80:
                val_disp = val_disp[:77] + "..."
            p(f"    [{r['db_name']}.{r['table_name']}.{r['field_name']} #{r['record_id']}]")
            p(f"      {r['sensitive_type']}({r['sensitive_level']}) = {val_disp!r}")

    # ── 8. unstructured_text 专项分析(权重 0.25 最高) ──────────
    p(section("8. unstructured_text 专项(F1 权重 0.25, 最重要)"))
    ut_rows = [r for r in rows if r["data_form"] == "unstructured_text"]
    if ut_rows:
        p(f"  共 {len(ut_rows)} 行")
        ut_types = Counter(r["sensitive_type"] for r in ut_rows)
        p("\n  类型分布:")
        for stype, cnt in ut_types.most_common():
            p(f"    {stype:<30} {cnt:>4}")

        # 按 sensitive_type 分组,每组抽 10 行
        p("\n  按类型抽样(每类最多 10 条):")
        by_type = defaultdict(list)
        for r in ut_rows:
            by_type[r["sensitive_type"]].append(r)
        for stype in sorted(by_type.keys(), key=lambda k: -len(by_type[k])):
            group = by_type[stype]
            p(f"\n    ━━ {stype} ({len(group)} 行) ━━")
            for r in group[:10]:
                val = r["extracted_value"]
                if len(val) > 60:
                    val = val[:57] + "..."
                p(f"      [{r['table_name']}.{r['field_name']} #{r['record_id']}]  {val!r}")
    else:
        p("  (无 unstructured_text 行)")

    # ── 9. encoded 专项(权重 0.20, 看有无 PASSWORD_OR_SECRET) ──
    p(section("9. encoded 专项(权重 0.20)"))
    enc_rows = [r for r in rows if r["data_form"] == "encoded"]
    if enc_rows:
        p(f"  共 {len(enc_rows)} 行")
        enc_types = Counter(r["sensitive_type"] for r in enc_rows)
        p("\n  类型分布:")
        for stype, cnt in enc_types.most_common():
            p(f"    {stype:<30} {cnt:>4}")
        if "PASSWORD_OR_SECRET" in enc_types:
            p("\n  ⚠️ encoded 里含 PASSWORD_OR_SECRET — 你代码里 scan_encoded_field 对密码")
            p("     字段直接 return [] 是个漏洞,需要修复")
        p("\n  全部 encoded 行:")
        for r in enc_rows:
            val = r["extracted_value"]
            if len(val) > 80:
                val = val[:77] + "..."
            p(f"    [{r['db_name']}.{r['table_name']}.{r['field_name']} #{r['record_id']}]")
            p(f"      {r['sensitive_type']} = {val!r}")
    else:
        p("  (无 encoded 行)")

    # ── 10. binary_blob 专项(决定是否引入 PyMuPDF) ─────────────
    p(section("10. binary_blob 专项(决定 PyMuPDF 价值)"))
    blob_rows = [r for r in rows if r["data_form"] == "binary_blob"]
    if blob_rows:
        p(f"  共 {len(blob_rows)} 行")
        blob_types = Counter(r["sensitive_type"] for r in blob_rows)
        p("\n  类型分布:")
        for stype, cnt in blob_types.most_common():
            p(f"    {stype:<30} {cnt:>4}")
        # 哪些表有 blob 答案
        blob_tables = Counter((r["db_name"], r["table_name"], r["field_name"]) for r in blob_rows)
        p("\n  涉及的 (库.表.字段):")
        for (dbn, tbl, fld), cnt in blob_tables.most_common():
            p(f"    {dbn}.{tbl}.{fld:<30} {cnt:>4}")
        p("\n  部分样本:")
        for r in blob_rows[:10]:
            val = r["extracted_value"]
            if len(val) > 80:
                val = val[:77] + "..."
            p(f"    [{r['table_name']}.{r['field_name']} #{r['record_id']}]  {r['sensitive_type']} = {val!r}")
    else:
        p("  (无 binary_blob 行)")

    # ── 11. semi_structured 专项 ────────────────────────────────
    p(section("11. semi_structured 专项(权重 0.20)"))
    sf_rows = [r for r in rows if r["data_form"] == "semi_structured"]
    if sf_rows:
        p(f"  共 {len(sf_rows)} 行")
        sf_types = Counter(r["sensitive_type"] for r in sf_rows)
        p("\n  类型分布:")
        for stype, cnt in sf_types.most_common():
            p(f"    {stype:<30} {cnt:>4}")
        sf_fields = Counter(r["field_name"] for r in sf_rows)
        p("\n  涉及 field_name top 10:")
        for fld, cnt in sf_fields.most_common(10):
            p(f"    {fld:<30} {cnt:>4}")
    else:
        p("  (无 semi_structured 行)")

    # ── 12. db_object 专项 ──────────────────────────────────────
    p(section("12. db_object 专项(权重 0.05, 验证扫描覆盖)"))
    do_rows = [r for r in rows if r["data_form"] == "db_object"]
    if do_rows:
        p(f"  共 {len(do_rows)} 行")
        p("\n  全部 db_object 行:")
        for r in do_rows:
            val = r["extracted_value"]
            if len(val) > 80:
                val = val[:77] + "..."
            p(f"    [{r['db_type']}/{r['db_name']}/{r['table_name']}] {r['field_name']}")
            p(f"      {r['sensitive_type']}({r['sensitive_level']}) = {val!r}")
    else:
        p("  (无 db_object 行)")

    # ── 13. structured 专项(权重最低 0.10 但量最大) ────────────
    p(section("13. structured 专项(权重 0.10)"))
    st_rows = [r for r in rows if r["data_form"] == "structured"]
    if st_rows:
        p(f"  共 {len(st_rows)} 行")
        st_types = Counter(r["sensitive_type"] for r in st_rows)
        p("\n  类型分布:")
        for stype, cnt in st_types.most_common():
            p(f"    {stype:<30} {cnt:>4}")
    else:
        p("  (无 structured 行)")

    # ── 14. extracted_value 长度分布 ────────────────────────────
    p(section("14. extracted_value 长度分布(看文本形态)"))
    len_buckets = Counter()
    for r in rows:
        L = len(r["extracted_value"])
        if L <= 10:
            len_buckets["≤10"] += 1
        elif L <= 20:
            len_buckets["11-20"] += 1
        elif L <= 50:
            len_buckets["21-50"] += 1
        elif L <= 100:
            len_buckets["51-100"] += 1
        else:
            len_buckets[">100"] += 1
    for bucket in ["≤10", "11-20", "21-50", "51-100", ">100"]:
        cnt = len_buckets.get(bucket, 0)
        p(f"  {bucket:<10} {cnt:>5}")

    return "\n".join(buf)


def main():
    path = find_csv(sys.argv)
    print(f"[INFO] 读取: {path}")
    rows = load_rows(path)
    print(f"[INFO] 载入 {len(rows)} 行\n")

    report = analyze(rows)
    print(report)

    out_path = "analyze_example_report.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"source: {path}\n")
        f.write(f"rows: {len(rows)}\n")
        f.write(report)
    print(f"\n[DONE] 报告已写入: {out_path}")
    print("       把这份文件内容或终端输出复制给 Claude 即可开始针对性优化。")


if __name__ == "__main__":
    main()
