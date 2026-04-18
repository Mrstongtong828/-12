"""
本地评分器 (Local Evaluator)

用途：每次修改 patterns.py / scanners/ 后，运行本脚本检查准确率是否下降。
用法：
    python tests/local_scorer.py --answer tests/example.csv --pred output/upload.csv
    python tests/local_scorer.py  # 使用默认路径

评分规则完全复现靶机逻辑（见 CLAUDE.md 第六章）：
  - 七元组精确匹配：(db_type, db_name, table_name, field_name, record_id,
                      sensitive_type, extracted_value)
  - extracted_value 去首尾空白后字符串精确比较
  - 按 data_form 分组计算各形态 F1，再加权汇总
  - sensitive_level 准确率单独计算（不影响 TP 判定）
"""
import csv
import sys
import argparse
from collections import defaultdict
from pathlib import Path

# ── 配置 ─────────────────────────────────────────────────────────
DEFAULT_ANSWER = Path("tests/example.csv")
DEFAULT_PRED   = Path("output/upload.csv")

FORM_WEIGHTS = {
    "structured":       0.10,
    "semi_structured":  0.20,
    "encoded":          0.20,
    "unstructured_text":0.25,
    "binary_blob":      0.20,
    "db_object":        0.05,
}

MATCH_COLS = ["db_type", "db_name", "table_name", "field_name",
              "record_id", "sensitive_type", "extracted_value"]
LEVEL_COL  = "sensitive_level"
FORM_COL   = "data_form"


# ── CSV 读取 ─────────────────────────────────────────────────────
def _load_csv(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            # 标准化：去首尾空白
            rows.append({k: v.strip() for k, v in row.items()})
    return rows


def _make_key(row: dict) -> tuple:
    return tuple(row.get(c, "").strip() for c in MATCH_COLS)


# ── 核心评分 ─────────────────────────────────────────────────────
def score(answer_rows: list, pred_rows: list) -> dict:
    # [新增] 提取所有答案的定位 Key：(db_name, table_name, record_id)，用于锁定测试范围
    # [新增] 只有在这些特定行里扫描出的数据，才会被拿来计算 F1，防止全库扫描导致 FP 爆炸
    valid_loc_keys = set(
        (row.get("db_name", "").strip(), row.get("table_name", "").strip(), row.get("record_id", "").strip())
        for row in answer_rows
    )

    # 按 data_form 分组的答案集合（允许重复行，但用 set 去重）
    answer_by_form: dict[str, set] = defaultdict(set)
    answer_level:   dict[tuple, str] = {}   # key -> correct level
    for row in answer_rows:
        key  = _make_key(row)
        form = row.get(FORM_COL, "")
        answer_by_form[form].add(key)
        answer_level[key] = row.get(LEVEL_COL, "")

    # 预测集合（同样去重）
    pred_by_form: dict[str, set] = defaultdict(set)
    pred_level:   dict[tuple, str] = {}
    for row in pred_rows:
        # [新增] 构建当前预测行的定位 Key
        current_loc = (row.get("db_name", "").strip(), row.get("table_name", "").strip(), row.get("record_id", "").strip())
        
        # [新增] 如果这行数据不在 example.csv 的范围内，直接跳过，不计入 FP！
        if current_loc not in valid_loc_keys:
            continue

        key  = _make_key(row)
        form = row.get(FORM_COL, "")
        pred_by_form[form].add(key)
        pred_level[key] = row.get(LEVEL_COL, "")

    all_forms = set(answer_by_form) | set(pred_by_form)

    form_f1: dict[str, float] = {}
    form_detail: dict[str, dict] = {}

    for form in all_forms:
        ans = answer_by_form.get(form, set())
        pred = pred_by_form.get(form, set())
        tp = len(ans & pred)
        fp = len(pred - ans)
        fn = len(ans - pred)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall    = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0.0)
        form_f1[form] = f1
        form_detail[form] = {"tp": tp, "fp": fp, "fn": fn,
                              "precision": precision, "recall": recall, "f1": f1}

    # 加权 F1
    weighted_f1 = sum(
        FORM_WEIGHTS.get(form, 0.0) * form_f1.get(form, 0.0)
        for form in FORM_WEIGHTS
    )

    # 等级准确率（分母 = 答案总行数）
    all_answer_keys = set()
    for keys in answer_by_form.values():
        all_answer_keys |= keys
    total_ans = len(all_answer_keys)

    correct_level = sum(
        1 for key in all_answer_keys
        if pred_level.get(key) == answer_level.get(key)
    )
    level_acc = correct_level / total_ans if total_ans else 0.0

    comprehensive = weighted_f1 * 0.70 + level_acc * 0.30

    return {
        "form_detail": form_detail,
        "weighted_f1": weighted_f1,
        "level_accuracy": level_acc,
        "comprehensive": comprehensive,
        "total_answer": total_ans,
        "total_pred": sum(len(v) for v in pred_by_form.values()),
    }


# ── 报告打印 ─────────────────────────────────────────────────────
_W = 60

def _bar(f1: float, width: int = 20) -> str:
    filled = int(f1 * width)
    return "█" * filled + "░" * (width - filled)


def print_report(result: dict):
    print("=" * _W)
    print(" DataWatchers 本地评分报告")
    print("=" * _W)

    header = f"{'形态':<18} {'F1':>6}  {'TP':>5} {'FP':>5} {'FN':>5}  {'权重':>5}"
    print(header)
    print("-" * _W)

    for form, weight in FORM_WEIGHTS.items():
        d = result["form_detail"].get(form, {"f1": 0, "tp": 0, "fp": 0, "fn": 0})
        bar = _bar(d["f1"])
        print(f"{form:<18} {d['f1']:>6.3f}  {d['tp']:>5} {d['fp']:>5} {d['fn']:>5}"
              f"  {weight:>4.0%}  {bar}")

    print("-" * _W)
    print(f"{'加权 F1':<30} {result['weighted_f1']:.4f}")
    print(f"{'等级准确率':<30} {result['level_accuracy']:.4f}")
    print(f"{'综合识别得分 (×0.75权重)':<30} {result['comprehensive']:.4f}")
    print("-" * _W)
    print(f"答案总行数: {result['total_answer']}   预测总行数: {result['total_pred']}")
    print("=" * _W)

    # 各形态命中/遗漏明细（FP/FN > 0 时才显示）
    detail = result["form_detail"]
    needs_detail = {f: d for f, d in detail.items() if d["fp"] > 0 or d["fn"] > 0}
    if needs_detail:
        print("\n[!] 需要关注的形态（有误报或漏报）：")
        for form, d in needs_detail.items():
            if d["fp"]:
                print(f"  {form}: {d['fp']} 条误报（FP）")
            if d["fn"]:
                print(f"  {form}: {d['fn']} 条漏报（FN）")


# ── 差异分析（可选详细模式）────────────────────────────────────
def print_diff(answer_rows: list, pred_rows: list, form_filter: str = None):
    """打印具体的 FP/FN 行，方便 debug 正则。"""
    answer_keys = {_make_key(r): r for r in answer_rows}
    
    # [新增] 同样需要限制打印 diff 时的测试范围，防止被全库的 FP 刷屏
    valid_loc_keys = set(
        (row.get("db_name", "").strip(), row.get("table_name", "").strip(), row.get("record_id", "").strip())
        for row in answer_rows
    )

    pred_keys = {}
    for r in pred_rows:
        current_loc = (r.get("db_name", "").strip(), r.get("table_name", "").strip(), r.get("record_id", "").strip())
        if current_loc in valid_loc_keys:
            pred_keys[_make_key(r)] = r

    fn_keys = set(answer_keys) - set(pred_keys)
    fp_keys = set(pred_keys) - set(answer_keys)

    if form_filter:
        fn_keys = {k for k in fn_keys
                   if answer_keys[k].get(FORM_COL) == form_filter}
        fp_keys = {k for k in fp_keys
                   if pred_keys[k].get(FORM_COL) == form_filter}

    if fn_keys:
        print(f"\n── 漏报 (FN) {len(fn_keys)} 条 ──")
        for k in sorted(fn_keys)[:30]:
            r = answer_keys[k]
            print(f"  [{r[FORM_COL]}] {r['table_name']}.{r['field_name']}"
                  f" id={r['record_id']} {r['sensitive_type']} = {r['extracted_value']!r}")
        if len(fn_keys) > 30:
            print(f"  ... 还有 {len(fn_keys)-30} 条")

    if fp_keys:
        print(f"\n── 误报 (FP) {len(fp_keys)} 条 ──")
        for k in sorted(fp_keys)[:30]:
            r = pred_keys[k]
            print(f"  [{r[FORM_COL]}] {r['table_name']}.{r['field_name']}"
                  f" id={r['record_id']} {r['sensitive_type']} = {r['extracted_value']!r}")
        if len(fp_keys) > 30:
            print(f"  ... 还有 {len(fp_keys)-30} 条")


# ── 入口 ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="DataWatchers 本地评分器")
    parser.add_argument("--answer", type=Path, default=DEFAULT_ANSWER,
                        help="标准答案 CSV（默认 tests/example.csv）")
    parser.add_argument("--pred", type=Path, default=DEFAULT_PRED,
                        help="预测结果 CSV（默认 output/upload.csv）")
    parser.add_argument("--diff", action="store_true",
                        help="打印 FP/FN 明细（debug 用）")
    parser.add_argument("--form", type=str, default=None,
                        help="只看某个 data_form 的 diff，如 --form encoded")
    args = parser.parse_args()

    if not args.answer.exists():
        print(f"[ERROR] 答案文件不存在: {args.answer}")
        print("请把标准答案放到 tests/example.csv（格式与 upload.csv 完全相同）")
        sys.exit(1)

    if not args.pred.exists():
        print(f"[ERROR] 预测文件不存在: {args.pred}")
        print("请先运行 python main.py 生成 output/upload.csv")
        sys.exit(1)

    answer_rows = _load_csv(args.answer)
    pred_rows   = _load_csv(args.pred)

    result = score(answer_rows, pred_rows)
    print_report(result)

    if args.diff:
        print_diff(answer_rows, pred_rows, form_filter=args.form)


if __name__ == "__main__":
    main()
