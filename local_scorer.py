"""
本地评分器 v3 (Local Evaluator)

严格对齐 README §6 官方评分公式：
  ① 分桶 F1（按 data_form）
  ② 加权 F1 = Σ(权重 × F1_form)
  ③ 等级准确率 = 等级正确的TP数 / 答案总行数      ← 官方分母就是"答案总行数"
  ④ 综合识别得分 = 加权F1 × 0.70 + 等级准确率 × 0.30   ← 靶机返回值

对比 v1 的工程改进（保留）：
  [A] 4元组 scope 过滤：(db_name, table_name, record_id, sensitive_type)
      README §五明确 example.csv 是 ~1% 抽样答案。用 record 粒度过滤会把
      "同 record 未被抽样的 type" 计成 FP，误导优化方向。
      数据验证：example.csv 的 566 个 record 里 552 个只出现 1 次 type，
      强证明 "同 record 未抽样的 type 在靶机完整答案里大概率是 TP"。
  [B] value-only F1（忽略 data_form）: 诊断"值扫错"vs"form分错"
  [C] form_mismatch 计数：值对但 form 标错的条数
  [D] --strict-scope 回退 v1 行为做对比；--normalize 激进值归一化

用法：
    python tests/local_scorer.py
    python tests/local_scorer.py --diff
    python tests/local_scorer.py --diff --form encoded --limit 50
    python tests/local_scorer.py --form-mismatch     # 额外打印 form 标错明细
    python tests/local_scorer.py --normalize         # NFKC+casefold 归一化
    python tests/local_scorer.py --strict-scope      # 退回 v1 粗粒度 scope
"""
import csv
import sys
import argparse
import unicodedata
from collections import defaultdict
from pathlib import Path

try:
    for _s in (sys.stdout, sys.stderr):
        if hasattr(_s, "reconfigure"):
            _s.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    _RICH = True
    _console = Console(legacy_windows=False, force_terminal=True)
except ImportError:
    _RICH = False
    _console = None

# ── 配置 ─────────────────────────────────────────────────────────
DEFAULT_ANSWER = Path("tests/example.csv")
DEFAULT_PRED   = Path("output/upload.csv")

# 官方 data_form 权重 (README §6.1②)
FORM_WEIGHTS = {
    "structured":        0.10,
    "semi_structured":   0.20,
    "encoded":           0.20,
    "unstructured_text": 0.25,
    "binary_blob":       0.20,
    "db_object":         0.05,
}

# 官方 7 元组匹配键 (README §3.4)：sensitive_level 不参与 TP 判定
FULL_MATCH_COLS = ["db_type", "db_name", "table_name", "field_name",
                   "record_id", "sensitive_type", "extracted_value"]
SCOPE_COLS_4 = ["db_name", "table_name", "record_id", "sensitive_type"]
SCOPE_COLS_3 = ["db_name", "table_name", "record_id"]

LEVEL_COL = "sensitive_level"
FORM_COL  = "data_form"


# ── 归一化 ───────────────────────────────────────────────────────
def _normalize_value(v, aggressive: bool):
    if not isinstance(v, str):
        return v
    s = v.strip()
    if not aggressive:
        return s
    return unicodedata.normalize("NFKC", s).casefold()


def _load_csv(path: Path, aggressive: bool = False) -> list:
    rows = []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            clean = {k: (v.strip() if isinstance(v, str) else v)
                     for k, v in row.items()}
            if "extracted_value" in clean:
                clean["extracted_value"] = _normalize_value(
                    clean["extracted_value"], aggressive)
            rows.append(clean)
    return rows


def _key_full(row: dict) -> tuple:
    return tuple(row.get(c, "").strip() for c in FULL_MATCH_COLS)


def _key_scope(row: dict, cols) -> tuple:
    return tuple(row.get(c, "").strip() for c in cols)


# ── 核心评分 ─────────────────────────────────────────────────────
def score(answer_rows: list, pred_rows: list, strict_scope: bool = False) -> dict:
    scope_cols = SCOPE_COLS_3 if strict_scope else SCOPE_COLS_4
    scope_keys = {_key_scope(r, scope_cols) for r in answer_rows}

    # 索引答案
    answer_by_form   = defaultdict(set)
    answer_full_keys = set()
    answer_level     = {}

    for row in answer_rows:
        key  = _key_full(row)
        form = row.get(FORM_COL, "")
        answer_by_form[form].add(key)
        answer_full_keys.add(key)
        answer_level[key] = row.get(LEVEL_COL, "")

    # 过滤预测
    pred_by_form    = defaultdict(set)
    pred_full_keys  = set()
    pred_level      = {}
    dropped_out_scope = 0

    for row in pred_rows:
        if _key_scope(row, scope_cols) not in scope_keys:
            dropped_out_scope += 1
            continue
        key  = _key_full(row)
        form = row.get(FORM_COL, "")
        pred_by_form[form].add(key)
        pred_full_keys.add(key)
        pred_level[key] = row.get(LEVEL_COL, "")

    # ── ① 分桶 F1 ────────────────────────────────────────────────
    all_forms   = set(answer_by_form) | set(pred_by_form)
    form_detail = {}
    for form in all_forms:
        ans  = answer_by_form.get(form, set())
        pred = pred_by_form.get(form, set())
        tp = len(ans & pred)
        fp = len(pred - ans)
        fn = len(ans - pred)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall    = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0.0)
        form_detail[form] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1,
        }

    # ── ② 加权 F1 ────────────────────────────────────────────────
    weighted_f1 = sum(
        FORM_WEIGHTS.get(f, 0.0) * form_detail.get(f, {"f1": 0.0})["f1"]
        for f in FORM_WEIGHTS
    )
    # 本地天花板：example.csv 只覆盖到的 form，对应权重之和
    # 抽样遗漏的 form（比如 example 里没有 db_object）会永远拿 0 分
    covered_weight_total = sum(
        FORM_WEIGHTS[f] for f in FORM_WEIGHTS if f in answer_by_form
    )
    uncovered_forms = [f for f in FORM_WEIGHTS if f not in answer_by_form]

    # ── ③ 等级准确率（官方: 分母 = 答案总行数）────────────────
    total_answer = len(answer_full_keys)
    correct_level_on_tp = sum(
        1 for k in answer_full_keys
        if k in pred_full_keys and pred_level.get(k) == answer_level.get(k)
    )
    level_acc_official = (
        correct_level_on_tp / total_answer if total_answer else 0.0
    )

    # 诊断用：仅在 TP 上算（剔除"漏报双重扣分"）
    tp_keys = answer_full_keys & pred_full_keys
    level_acc_tp_only = (
        correct_level_on_tp / len(tp_keys) if tp_keys else 0.0
    )

    # ── ④ 综合识别得分 (靶机返回) ────────────────────────────────
    comprehensive = weighted_f1 * 0.70 + level_acc_official * 0.30

    # ── 诊断：value-only F1 ─────────────────────────────────────
    tp_v = len(answer_full_keys & pred_full_keys)
    fp_v = len(pred_full_keys - answer_full_keys)
    fn_v = len(answer_full_keys - pred_full_keys)
    p_v = tp_v / (tp_v + fp_v) if (tp_v + fp_v) else 0.0
    r_v = tp_v / (tp_v + fn_v) if (tp_v + fn_v) else 0.0
    f1_v = (2 * p_v * r_v / (p_v + r_v)) if (p_v + r_v) else 0.0

    # 诊断：值对但 form 错（官方会双重扣分）
    tp_bucketed_sum = sum(d["tp"] for d in form_detail.values())
    form_mismatch = tp_v - tp_bucketed_sum

    return {
        "strict_scope": strict_scope,
        "form_detail": form_detail,
        "weighted_f1": weighted_f1,
        "local_ceiling_f1":  covered_weight_total,
        "uncovered_forms":   uncovered_forms,
        "level_acc_official": level_acc_official,
        "level_acc_tp_only":  level_acc_tp_only,
        "comprehensive":      comprehensive,
        "correct_level":      correct_level_on_tp,
        "total_answer":       total_answer,
        "total_tp":           len(tp_keys),
        "value_f1": f1_v,
        "value_precision": p_v,
        "value_recall": r_v,
        "value_tp": tp_v, "value_fp": fp_v, "value_fn": fn_v,
        "form_mismatch": form_mismatch,
        "total_pred_in_scope": len(pred_full_keys),
        "total_pred_raw": len(pred_rows),
        "dropped_out_scope": dropped_out_scope,
    }


# ── 报告打印 ─────────────────────────────────────────────────────
_W = 72


def _bar(f1: float, width: int = 20) -> str:
    filled = int(f1 * width)
    return "█" * filled + "░" * (width - filled)


def _f1_color(f1: float) -> str:
    if f1 >= 0.8:
        return "green"
    if f1 >= 0.5:
        return "yellow"
    return "red"


def _f1_bar_rich(f1: float, width: int = 20) -> Text:
    filled = int(f1 * width)
    color = _f1_color(f1)
    t = Text()
    t.append("█" * filled, style=color)
    t.append("░" * (width - filled), style="dim")
    return t


def _print_report_rich(result: dict):
    scope_label = "3元组 (v1 兼容)" if result["strict_scope"] else "4元组 (推荐)"
    _console.print(Panel.fit(
        Text.assemble(
            ("本地评分报告 v3", "bold cyan"),
            ("   对齐 README §6 官方公式\n", "dim"),
            ("Scope 模式: ", ""),
            (scope_label, "bold"),
        ),
        border_style="cyan",
    ))

    # ── [A] 分桶 F1 ─────────────────────────────────────────────
    table_a = Table(
        title="[A] 分桶 F1  —  README §6.1 ①",
        box=box.SIMPLE_HEAVY, header_style="bold",
        title_justify="left",
    )
    table_a.add_column("形态", style="cyan", no_wrap=True)
    table_a.add_column("F1", justify="right")
    table_a.add_column("TP", justify="right", style="green")
    table_a.add_column("FP", justify="right", style="red")
    table_a.add_column("FN", justify="right", style="yellow")
    table_a.add_column("权重", justify="right", style="dim")
    table_a.add_column("进度", no_wrap=True)

    for form, weight in FORM_WEIGHTS.items():
        d = result["form_detail"].get(form, {"f1": 0, "tp": 0, "fp": 0, "fn": 0})
        f1_text = Text(f"{d['f1']:.3f}", style=_f1_color(d["f1"]))
        table_a.add_row(
            form, f1_text,
            str(d["tp"]), str(d["fp"]), str(d["fn"]),
            f"{weight:.0%}", _f1_bar_rich(d["f1"]),
        )
    _console.print(table_a)

    extra = [f for f in result["form_detail"] if f not in FORM_WEIGHTS]
    if extra:
        _console.print("[bold red][!] 未知 data_form（不计入加权分，检查拼写）：[/]")
        for form in extra:
            d = result["form_detail"][form]
            _console.print(
                f"   [red]{form:<18}[/] F1={d['f1']:.3f} "
                f"TP={d['tp']} FP={d['fp']} FN={d['fn']}"
            )

    # ── [B] 加权 F1 + 天花板 ─────────────────────────────────────
    wf1 = result["weighted_f1"]
    b_text = Text.assemble(
        ("加权 F1 = Σ(权重 × F1_form)  →  ", ""),
        (f"{wf1:.4f}", f"bold {_f1_color(wf1)}"),
    )
    ceil_f1 = result["local_ceiling_f1"]
    ceil_comp = ceil_f1 * 0.70 + 1.0 * 0.30
    if ceil_f1 < 0.999:
        achieve = wf1 / ceil_f1 * 100 if ceil_f1 > 0 else 0.0
        b_text.append(
            f"\n[天花板] 本地完美预测最多 {ceil_f1:.4f}（达成率 {achieve:.1f}%）\n",
            style="dim yellow",
        )
        b_text.append(
            f"         抽样未覆盖的 form: {result['uncovered_forms']}\n",
            style="dim",
        )
        b_text.append(
            f"         对应综合识别得分本地天花板: {ceil_comp:.4f}",
            style="dim yellow",
        )
    _console.print(Panel(b_text, title="[B] 加权 F1", border_style="cyan",
                         title_align="left"))

    # ── [C] 等级准确率 ───────────────────────────────────────────
    level_acc = result["level_acc_official"]
    c_text = Text.assemble(
        ("公式: 等级正确的TP数 / 答案总行数\n", "dim"),
        (f"= {result['correct_level']} / {result['total_answer']}  = ", ""),
        (f"{level_acc:.4f}", f"bold {_f1_color(level_acc)}"),
        (f"\n诊断: TP-only 等级准确率 = "
         f"{result['correct_level']}/{result['total_tp']} "
         f"= {result['level_acc_tp_only']:.4f}", "dim"),
    )
    _console.print(Panel(c_text, title="[C] 等级准确率  —  README §6.1 ③",
                         border_style="cyan", title_align="left"))

    # ── [D] 综合识别得分 ────────────────────────────────────────
    comp = result["comprehensive"]
    d_text = Text.assemble(
        ("综合识别得分 = 加权F1 × 0.70 + 等级准确率 × 0.30\n", ""),
        (f"= {wf1:.4f}×0.70 + {level_acc:.4f}×0.30\n", "dim"),
        ("= ", ""),
        (f"{comp:.4f}", f"bold {_f1_color(comp)}"),
        ("   ← 对应靶机返回值", "dim"),
    )
    _console.print(Panel(d_text, title="[D] 综合识别得分 (靶机)",
                         border_style="bright_cyan", title_align="left"))

    # ── [E] Value-only F1 ───────────────────────────────────────
    table_e = Table(
        title="[E] Value-only F1  (忽略 data_form，诊断用)",
        box=box.SIMPLE, title_justify="left",
    )
    table_e.add_column("指标", style="cyan")
    table_e.add_column("值", justify="right")
    vf1 = result["value_f1"]
    table_e.add_row("precision", f"{result['value_precision']:.4f}")
    table_e.add_row("recall",    f"{result['value_recall']:.4f}")
    table_e.add_row("f1",        Text(f"{vf1:.4f}", style=_f1_color(vf1)))
    table_e.add_row("TP", Text(str(result["value_tp"]), style="green"))
    table_e.add_row("FP", Text(str(result["value_fp"]), style="red"))
    table_e.add_row("FN", Text(str(result["value_fn"]), style="yellow"))
    _console.print(table_e)

    mm = result["form_mismatch"]
    if mm > 0:
        _console.print(Panel(
            Text.assemble(
                (f"值找对但 data_form 标错: {mm} 条\n", "bold yellow"),
                ("官方分桶会把这些条目计为 FP+FN（双重扣分）。"
                 "修 dispatcher 路由逻辑能一次吃下两倍收益。", "dim"),
            ),
            border_style="yellow", title="[!] Form 标错提示",
            title_align="left",
        ))

    # ── [F] 数据概况 ────────────────────────────────────────────
    table_f = Table(title="[F] 数据概况", box=box.SIMPLE, title_justify="left")
    table_f.add_column("项", style="cyan")
    table_f.add_column("值", justify="right")
    table_f.add_row("答案去重后总行数", str(result["total_answer"]))
    table_f.add_row("预测原始总行数", str(result["total_pred_raw"]))
    table_f.add_row("预测落入 scope 的行数", str(result["total_pred_in_scope"]))
    note = " (v1 会把这些算成 FP)" if not result["strict_scope"] else ""
    table_f.add_row(
        "预测被 scope 过滤的行数",
        Text(f"{result['dropped_out_scope']}{note}", style="dim"),
    )
    _console.print(table_f)

    # ── 提示 ────────────────────────────────────────────────────
    _console.print(Panel(
        "[dim]example.csv 是 ~1% 抽样答案（README §五），本地分数只反映抽到\n"
        "的那部分。靶机用完整答案集，实际分数会有差异；value_fp 中若看到\n"
        "大量合理敏感值，说明抽样遗漏的 TP 比较多，不要为了消灭它们而收紧\n"
        "正则，会反过来压低靶机 recall。[/]",
        border_style="dim", title="[i] 抽样说明", title_align="left",
    ))

    needs = {f: d for f, d in result["form_detail"].items()
             if d["fp"] > 0 or d["fn"] > 0}
    if needs:
        t_need = Table(
            title="[!] 需要关注的形态（有误报或漏报）",
            box=box.SIMPLE, title_justify="left", title_style="bold yellow",
        )
        t_need.add_column("形态", style="cyan")
        t_need.add_column("FP", justify="right", style="red")
        t_need.add_column("FN", justify="right", style="yellow")
        for form, d in sorted(needs.items(),
                              key=lambda x: -x[1]["fp"] - x[1]["fn"]):
            t_need.add_row(form, str(d["fp"]), str(d["fn"]))
        _console.print(t_need)


def _print_report_plain(result: dict):
    print("=" * _W)
    print(" 本地评分报告 v3   (对齐 README §6 官方公式)")
    print(f" Scope 模式: {'3元组 (v1 兼容)' if result['strict_scope'] else '4元组 (推荐)'}")
    print("=" * _W)

    print("\n[A] 分桶 F1 —— README §6.1 ①")
    print(f"{'形态':<20} {'F1':>6}  {'TP':>5} {'FP':>5} {'FN':>5}  {'权重':>5}")
    print("-" * _W)
    for form, weight in FORM_WEIGHTS.items():
        d = result["form_detail"].get(form, {"f1": 0, "tp": 0, "fp": 0, "fn": 0})
        bar = _bar(d["f1"])
        print(f"{form:<20} {d['f1']:>6.3f}  "
              f"{d['tp']:>5} {d['fp']:>5} {d['fn']:>5}  "
              f"{weight:>4.0%}  {bar}")
    extra = [f for f in result["form_detail"] if f not in FORM_WEIGHTS]
    if extra:
        print("-" * _W)
        print("[!] 未知 data_form（不计入加权分，检查拼写）：")
        for form in extra:
            d = result["form_detail"][form]
            print(f"   {form:<18} F1={d['f1']:.3f}  TP={d['tp']} FP={d['fp']} FN={d['fn']}")

    print("-" * _W)
    print(f"[B] 加权 F1 = Σ(权重 × F1_form)  →  {result['weighted_f1']:.4f}")
    ceil_f1 = result["local_ceiling_f1"]
    ceil_comp = ceil_f1 * 0.70 + 1.0 * 0.30
    if ceil_f1 < 0.999:
        print(f"    [天花板] 本地完美预测最多只能拿 {ceil_f1:.4f}（即 "
              f"{result['weighted_f1']/ceil_f1*100:.1f}% 达成率）")
        print(f"             原因: example.csv 缺以下 form 的样本: "
              f"{result['uncovered_forms']}")
        print(f"             对应综合识别得分本地天花板: {ceil_comp:.4f}")

    print(f"\n[C] 等级准确率 —— README §6.1 ③")
    print(f"    公式: 等级正确的TP数 / 答案总行数")
    print(f"    = {result['correct_level']} / {result['total_answer']}  "
          f"= {result['level_acc_official']:.4f}")
    print(f"    （诊断: TP-only 等级准确率 = "
          f"{result['correct_level']}/{result['total_tp']} = "
          f"{result['level_acc_tp_only']:.4f}）")

    print(f"\n[D] 综合识别得分 = 加权F1×0.70 + 等级准确率×0.30")
    print(f"    = {result['weighted_f1']:.4f}×0.70 + "
          f"{result['level_acc_official']:.4f}×0.30")
    print(f"    = {result['comprehensive']:.4f}   ← 对应靶机返回值")

    print(f"\n[E] Value-only F1（忽略 data_form，诊断用）")
    print(f"    precision={result['value_precision']:.4f}  "
          f"recall={result['value_recall']:.4f}  "
          f"f1={result['value_f1']:.4f}")
    print(f"    TP={result['value_tp']}  FP={result['value_fp']}  FN={result['value_fn']}")
    mm = result["form_mismatch"]
    if mm > 0:
        print(f"    [!] 值找对但 data_form 标错: {mm} 条")
        print(f"        官方分桶会把这些条目计为 FP+FN（双重扣分），"
              f"修 dispatcher 路由逻辑能一次吃下两倍收益")

    print(f"\n[F] 数据概况")
    print(f"    答案去重后总行数          : {result['total_answer']}")
    print(f"    预测原始总行数            : {result['total_pred_raw']}")
    print(f"    预测落入 scope 的行数     : {result['total_pred_in_scope']}")
    print(f"    预测被 scope 过滤的行数   : {result['dropped_out_scope']}"
          + (" (v1 会把这些算成 FP)" if not result['strict_scope'] else ""))
    print("=" * _W)

    print("")
    print("[i] example.csv 是 ~1% 抽样答案（README §五），本地分数只反映")
    print("    抽到的那部分的识别情况。靶机用完整答案集，实际分数会有差异；")
    print("    value_fp 中若看到大量合理敏感值，说明抽样遗漏的 TP 比较多，")
    print("    不要为了消灭它们而收紧正则，会反过来压低靶机 recall。")

    needs = {f: d for f, d in result["form_detail"].items()
             if d["fp"] > 0 or d["fn"] > 0}
    if needs:
        print("\n[!] 需要关注的形态（有误报或漏报）：")
        for form, d in sorted(needs.items(), key=lambda x: -x[1]["fp"] - x[1]["fn"]):
            print(f"    {form:<20} FP={d['fp']:<4} FN={d['fn']:<4}")


def print_report(result: dict):
    if _RICH:
        _print_report_rich(result)
    else:
        _print_report_plain(result)


# ── 差异分析 ─────────────────────────────────────────────────────
def print_diff(answer_rows: list, pred_rows: list,
               form_filter=None, strict_scope: bool = False,
               show_form_mismatch: bool = False, limit: int = 30):
    scope_cols = SCOPE_COLS_3 if strict_scope else SCOPE_COLS_4
    scope_keys = {_key_scope(r, scope_cols) for r in answer_rows}

    answer_map = {_key_full(r): r for r in answer_rows}
    pred_map = {}
    for r in pred_rows:
        if _key_scope(r, scope_cols) in scope_keys:
            pred_map[_key_full(r)] = r

    fn_keys = set(answer_map) - set(pred_map)
    fp_keys = set(pred_map) - set(answer_map)

    if form_filter:
        fn_keys = {k for k in fn_keys
                   if answer_map[k].get(FORM_COL) == form_filter}
        fp_keys = {k for k in fp_keys
                   if pred_map[k].get(FORM_COL) == form_filter}

    def _fmt(r: dict) -> str:
        return (f"[{r.get(FORM_COL, ''):<18}] "
                f"{r.get('table_name',''):<24}."
                f"{r.get('field_name',''):<22} "
                f"id={r.get('record_id',''):<6} "
                f"{r.get('sensitive_type',''):<22} "
                f"= {r.get('extracted_value','')!r}")

    def _diff_table(title: str, title_style: str, border: str,
                    keys, source_map):
        t = Table(title=title, box=box.SIMPLE, title_justify="left",
                  title_style=title_style, border_style=border)
        t.add_column("form", style="cyan", no_wrap=True)
        t.add_column("table.field", no_wrap=True)
        t.add_column("id", justify="right", style="dim")
        t.add_column("type", style="magenta")
        t.add_column("value", overflow="fold")
        for k in sorted(keys)[:limit]:
            r = source_map[k]
            t.add_row(
                r.get(FORM_COL, ""),
                f"{r.get('table_name','')}.{r.get('field_name','')}",
                str(r.get("record_id", "")),
                r.get("sensitive_type", ""),
                repr(r.get("extracted_value", "")),
            )
        _console.print(t)
        if len(keys) > limit:
            _console.print(
                f"[dim]  ... 还有 {len(keys)-limit} 条（用 --limit N 调整）[/]"
            )

    if _RICH:
        if fn_keys:
            _diff_table(f"漏报 (FN) {len(fn_keys)} 条", "bold yellow",
                        "yellow", fn_keys, answer_map)
        if fp_keys:
            _diff_table(f"误报 (FP) {len(fp_keys)} 条", "bold red",
                        "red", fp_keys, pred_map)
    else:
        if fn_keys:
            print(f"\n── 漏报 (FN) {len(fn_keys)} 条 ──")
            for k in sorted(fn_keys)[:limit]:
                print("  " + _fmt(answer_map[k]))
            if len(fn_keys) > limit:
                print(f"  ... 还有 {len(fn_keys)-limit} 条（用 --limit N 调整）")
        if fp_keys:
            print(f"\n── 误报 (FP) {len(fp_keys)} 条 ──")
            for k in sorted(fp_keys)[:limit]:
                print("  " + _fmt(pred_map[k]))
            if len(fp_keys) > limit:
                print(f"  ... 还有 {len(fp_keys)-limit} 条（用 --limit N 调整）")

    if show_form_mismatch:
        mismatches = []
        for k in set(answer_map) & set(pred_map):
            af = answer_map[k].get(FORM_COL, "")
            pf = pred_map[k].get(FORM_COL, "")
            if af != pf:
                mismatches.append((k, af, pf))
        if mismatches:
            if _RICH:
                t = Table(
                    title=f"Form 标错 {len(mismatches)} 条"
                          f"（值对但 data_form 不同，官方双重扣分）",
                    box=box.SIMPLE, title_justify="left",
                    title_style="bold yellow", border_style="yellow",
                )
                t.add_column("答案 form", style="green", no_wrap=True)
                t.add_column("预测 form", style="red", no_wrap=True)
                t.add_column("table.field", no_wrap=True)
                t.add_column("id", justify="right", style="dim")
                t.add_column("type", style="magenta")
                t.add_column("value", overflow="fold")
                for k, af, pf in mismatches[:limit]:
                    r = pred_map[k]
                    t.add_row(
                        af, pf,
                        f"{r.get('table_name','')}.{r.get('field_name','')}",
                        str(r.get("record_id", "")),
                        r.get("sensitive_type", ""),
                        repr(r.get("extracted_value", "")),
                    )
                _console.print(t)
                if len(mismatches) > limit:
                    _console.print(
                        f"[dim]  ... 还有 {len(mismatches)-limit} 条[/]"
                    )
            else:
                print(f"\n── Form 标错 {len(mismatches)} 条 （值对但 data_form 不同，"
                      f"官方双重扣分）──")
                for k, af, pf in mismatches[:limit]:
                    r = pred_map[k]
                    print(f"  答案form={af:<18} 预测form={pf:<18} | "
                          f"{r.get('table_name','')}.{r.get('field_name','')} "
                          f"id={r.get('record_id','')} "
                          f"{r.get('sensitive_type','')} = {r.get('extracted_value','')!r}")
                if len(mismatches) > limit:
                    print(f"  ... 还有 {len(mismatches)-limit} 条")


# ── 入口 ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="本地评分器 v3 (对齐官方公式)")
    parser.add_argument("--answer", type=Path, default=DEFAULT_ANSWER,
                        help="标准答案 CSV（默认 tests/example.csv）")
    parser.add_argument("--pred", type=Path, default=DEFAULT_PRED,
                        help="预测结果 CSV（默认 output/upload.csv）")
    parser.add_argument("--diff", action="store_true",
                        help="打印 FP/FN 明细")
    parser.add_argument("--form", type=str, default=None,
                        help="只看某个 data_form 的 diff")
    parser.add_argument("--limit", type=int, default=30,
                        help="diff 单类最多打印条数")
    parser.add_argument("--form-mismatch", action="store_true",
                        help="在 --diff 基础上，额外打印 form 标错的条目")
    parser.add_argument("--normalize", action="store_true",
                        help="激进归一化（NFKC+casefold）再比对；默认仅 strip")
    parser.add_argument("--strict-scope", action="store_true",
                        help="退回 v1 的 3元组 scope（调试对比用）")
    args = parser.parse_args()

    if not args.answer.exists():
        print(f"[ERROR] 答案文件不存在: {args.answer}")
        sys.exit(1)
    if not args.pred.exists():
        print(f"[ERROR] 预测文件不存在: {args.pred}")
        print("请先运行 python main.py 生成 output/upload.csv")
        sys.exit(1)

    answer_rows = _load_csv(args.answer, aggressive=args.normalize)
    pred_rows   = _load_csv(args.pred,   aggressive=args.normalize)

    result = score(answer_rows, pred_rows, strict_scope=args.strict_scope)
    print_report(result)

    if args.diff or args.form_mismatch:
        print_diff(
            answer_rows, pred_rows,
            form_filter=args.form,
            strict_scope=args.strict_scope,
            show_form_mismatch=args.form_mismatch,
            limit=args.limit,
        )


if __name__ == "__main__":
    main()
