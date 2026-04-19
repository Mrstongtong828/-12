"""
对比 upload.csv(你的输出) vs example.csv(官方答案样本)

用法:
    python diff_upload_vs_example.py

默认读:
    output/upload.csv
    example6.csv

输出:
    diff_report.txt  —— 完整对比报告

注意: example.csv 只是约 1% 的样本,不是全量答案。
     TP/FN 数字需要相对看,不是绝对分数。
"""
import csv
import os
import sys
from collections import Counter, defaultdict


UPLOAD_PATH_CANDIDATES = ["output/upload.csv", "upload.csv"]
EXAMPLE_PATH_CANDIDATES = ["example6.csv", "example5.csv", "example.csv"]


def find_file(candidates, label):
    for p in candidates:
        if os.path.isfile(p):
            return p
    print(f"[ERR] 找不到 {label}。尝试过: {candidates}")
    sys.exit(1)


def load_rows(path):
    rows = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({k: (v or "").strip() for k, v in r.items()})
    return rows


def make_key(r):
    """七元组精确匹配键(README 3.4 节定义)。"""
    return (
        r.get("db_type", "").lower(),
        r.get("db_name", ""),
        r.get("table_name", ""),
        r.get("field_name", ""),
        str(r.get("record_id", "")).strip(),
        r.get("sensitive_type", ""),
        r.get("extracted_value", "").strip(),
    )


def format_row(r):
    return (f"[{r.get('db_type')}/{r.get('db_name')}.{r.get('table_name')}"
            f".{r.get('field_name')} #{r.get('record_id')}] "
            f"{r.get('data_form')}/{r.get('sensitive_type')}({r.get('sensitive_level')}) "
            f"= {r.get('extracted_value')!r}")


def main():
    upload_path = find_file(UPLOAD_PATH_CANDIDATES, "upload.csv")
    example_path = find_file(EXAMPLE_PATH_CANDIDATES, "example.csv")

    print(f"[INFO] upload: {upload_path}")
    print(f"[INFO] example: {example_path}")

    upload = load_rows(upload_path)
    example = load_rows(example_path)

    print(f"[INFO] upload 行数: {len(upload)}")
    print(f"[INFO] example 行数: {len(example)}\n")

    upload_map = {}
    for r in upload:
        k = make_key(r)
        upload_map[k] = r  # 同键重复后者覆盖前者

    example_map = {}
    for r in example:
        k = make_key(r)
        example_map[k] = r

    upload_keys = set(upload_map.keys())
    example_keys = set(example_map.keys())

    tp_keys = upload_keys & example_keys
    # FP = upload 有, example 没有(但注意 example 只是样本,FP 里可能含真答案)
    fp_keys = upload_keys - example_keys
    # FN = example 有, upload 没有
    fn_keys = example_keys - upload_keys

    buf = []
    p = buf.append

    def section(t):
        p("\n" + "═" * 70)
        p(f"  {t}")
        p("═" * 70)

    section("0. 汇总")
    p(f"  upload 总行: {len(upload)}")
    p(f"  example 总行: {len(example)} (只是样本,不是全量答案)")
    p(f"  TP (两边都有, 精确匹配): {len(tp_keys)}")
    p(f"  FP (upload 有, example 没有): {len(fp_keys)}  ← 含真答案 + 真误报")
    p(f"  FN (example 有, upload 没有): {len(fn_keys)}  ← 纯漏报, 最重要")

    # ── 1. FN 按 data_form 分布 ──────────────────────────────────
    section("1. FN(漏报) 按 data_form 分布 —— 重点优化对象")
    fn_by_form = Counter(example_map[k].get("data_form", "?") for k in fn_keys)
    total_by_form = Counter(r.get("data_form", "?") for r in example)
    for form in sorted(total_by_form.keys(), key=lambda f: -total_by_form[f]):
        missed = fn_by_form.get(form, 0)
        total = total_by_form[form]
        pct = 100.0 * missed / total if total else 0
        p(f"  {form:<22} 漏 {missed:>3}/{total:<3}  ({pct:5.1f}%)")

    # ── 2. FN 按 sensitive_type 分布 ─────────────────────────────
    section("2. FN 按 sensitive_type 分布")
    fn_by_type = Counter(example_map[k].get("sensitive_type", "?") for k in fn_keys)
    total_by_type = Counter(r.get("sensitive_type", "?") for r in example)
    for stype in sorted(total_by_type.keys(), key=lambda s: -total_by_type[s]):
        missed = fn_by_type.get(stype, 0)
        total = total_by_type[stype]
        pct = 100.0 * missed / total if total else 0
        mark = " ⚠️" if pct > 30 else ""
        p(f"  {stype:<30} 漏 {missed:>3}/{total:<3}  ({pct:5.1f}%){mark}")

    # ── 3. FN 全量清单(按 form 分组) ────────────────────────────
    section("3. FN 全量清单 —— 这些是你代码没识别到的官方答案")
    fn_grouped = defaultdict(list)
    for k in fn_keys:
        r = example_map[k]
        fn_grouped[r.get("data_form", "?")].append(r)
    for form in sorted(fn_grouped.keys()):
        rows = fn_grouped[form]
        p(f"\n  ━━━ {form} ({len(rows)} 条漏报) ━━━")
        for r in rows:
            p(f"    {format_row(r)}")

    # ── 4. FP 按 field_name 分布(只看可能的真 FP) ──────────────
    section("4. FP 的 field_name top 20(可能是你误报的)")
    # 为了减少噪声: 只统计那些 example 里该 (db,table,field) 出现过的 FP
    # (这些位置是官方认为有敏感数据的, 你的 FP 更可能是误报而不是真 TP 没出现在样本)
    example_positions = set(
        (r.get("db_name"), r.get("table_name"), r.get("field_name"))
        for r in example
    )
    fp_in_covered = [k for k in fp_keys
                     if (upload_map[k].get("db_name"),
                         upload_map[k].get("table_name"),
                         upload_map[k].get("field_name")) in example_positions]
    p(f"  [说明] 仅看 example 覆盖的 (db,table,field) 位置内的 FP,共 {len(fp_in_covered)} 条")
    fp_field_counter = Counter(upload_map[k].get("field_name", "?") for k in fp_in_covered)
    for fld, cnt in fp_field_counter.most_common(20):
        p(f"  {fld:<35} {cnt:>4}")

    # ── 5. FP 样本(按 sensitive_type 分组, 每组 10 条) ────────
    section("5. FP 样本(每种类型 10 条)—— 看误报 pattern")
    fp_by_type = defaultdict(list)
    for k in fp_in_covered:
        r = upload_map[k]
        fp_by_type[r.get("sensitive_type", "?")].append(r)
    for stype in sorted(fp_by_type.keys(), key=lambda s: -len(fp_by_type[s])):
        rows = fp_by_type[stype]
        p(f"\n  ━━━ {stype} ({len(rows)} 条 FP) ━━━")
        for r in rows[:10]:
            p(f"    {format_row(r)}")

    # ── 6. 每种 data_form 的 F1(相对 example 样本) ────────────
    section("6. 分层 F1(注意:相对 example 样本,不是真实 F1)")
    p(f"  {'data_form':<22} {'TP':>5} {'FP':>5} {'FN':>5} {'Prec':>7} {'Recall':>7} {'F1':>7}")
    for form in sorted(total_by_form.keys(), key=lambda f: -total_by_form[f]):
        tp_f = sum(1 for k in tp_keys if example_map[k].get("data_form") == form)
        fn_f = fn_by_form.get(form, 0)
        fp_f = sum(1 for k in fp_in_covered if upload_map[k].get("data_form") == form)
        if tp_f + fp_f == 0:
            prec = 0.0
        else:
            prec = tp_f / (tp_f + fp_f)
        if tp_f + fn_f == 0:
            rec = 0.0
        else:
            rec = tp_f / (tp_f + fn_f)
        if prec + rec == 0:
            f1 = 0.0
        else:
            f1 = 2 * prec * rec / (prec + rec)
        p(f"  {form:<22} {tp_f:>5} {fp_f:>5} {fn_f:>5} {prec:>7.3f} {rec:>7.3f} {f1:>7.3f}")

    # ── 7. 加权总 F1 ────────────────────────────────────────────
    section("7. 加权总 F1(按官方权重)")
    WEIGHTS = {
        "structured": 0.10, "semi_structured": 0.20, "encoded": 0.20,
        "unstructured_text": 0.25, "binary_blob": 0.20, "db_object": 0.05,
    }
    total_weighted = 0.0
    total_weight = 0.0
    for form, w in WEIGHTS.items():
        tp_f = sum(1 for k in tp_keys if example_map[k].get("data_form") == form)
        fn_f = fn_by_form.get(form, 0)
        fp_f = sum(1 for k in fp_in_covered if upload_map[k].get("data_form") == form)
        if tp_f + fp_f == 0:
            prec = 0.0
        else:
            prec = tp_f / (tp_f + fp_f)
        if tp_f + fn_f == 0:
            rec = 0.0
        else:
            rec = tp_f / (tp_f + fn_f)
        f1 = 0.0 if prec + rec == 0 else 2 * prec * rec / (prec + rec)
        if tp_f + fn_f > 0:
            total_weighted += w * f1
            total_weight += w
        p(f"  {form:<22} F1={f1:.3f}  weight={w}")
    if total_weight > 0:
        p(f"\n  归一化加权 F1: {total_weighted / total_weight:.3f}")
        p(f"  原始加权 F1:   {total_weighted:.3f} (分母 {total_weight})")

    # ── 8. level 准确率 ──────────────────────────────────────────
    section("8. 等级准确率(TP 行里 level 填对的比例)")
    lvl_right = 0
    lvl_wrong = 0
    lvl_wrong_samples = []
    for k in tp_keys:
        u_lvl = upload_map[k].get("sensitive_level", "")
        e_lvl = example_map[k].get("sensitive_level", "")
        if u_lvl == e_lvl:
            lvl_right += 1
        else:
            lvl_wrong += 1
            if len(lvl_wrong_samples) < 10:
                lvl_wrong_samples.append((k, u_lvl, e_lvl))
    if lvl_right + lvl_wrong > 0:
        acc = lvl_right / (lvl_right + lvl_wrong)
        p(f"  等级正确: {lvl_right}/{lvl_right + lvl_wrong}  ({acc*100:.1f}%)")
    if lvl_wrong_samples:
        p("\n  错配样本(前 10):")
        for k, u, e in lvl_wrong_samples:
            p(f"    {k[5]}  你={u}  答案={e}")

    out = "\n".join(buf)
    print(out)

    with open("diff_report.txt", "w", encoding="utf-8") as f:
        f.write(out)
    print("\n[DONE] 报告写入: diff_report.txt")


if __name__ == "__main__":
    main()
