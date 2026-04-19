"""
终端可视化日志模块(安全版)。

关键改动:
  旧版 rich 启用后台刷新线程(refresh_per_second=4),和 PaddleOCR 的
  OMP 线程在同一进程里争用 → 段错误。新版把 rich 改成 auto_refresh=False,
  完全消除后台线程,每次状态变化手动 refresh 一次。

  结果:
    - 可以同时用 rich 的彩色进度条 + PaddleOCR(哪怕在主进程跑)
    - 现在 OCR 已经外包到子进程,本主进程更轻,rich 用得更放心
    - 默认开启;若仍想回退到 plain print,设 USE_RICH_PROGRESS=0

文件日志:所有 WARNING/ERROR 写入 scan_error.log,不污染终端。
"""
import logging
import threading
import os
from datetime import datetime

_USE_RICH = os.environ.get("USE_RICH_PROGRESS", "1") == "1"

_RICH_AVAILABLE = False
if _USE_RICH:
    try:
        from rich.progress import (
            Progress, SpinnerColumn, TextColumn,
            BarColumn, MofNCompleteColumn, TimeElapsedColumn,
        )
        from rich.console import Console
        _RICH_AVAILABLE = True
    except ImportError:
        _RICH_AVAILABLE = False


_LOG_FILE = "scan_error.log"

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(_LOG_FILE, encoding="utf-8")],
)
_file_logger = logging.getLogger("scan")


class ScanLogger:
    """
    用法:

        with ScanLogger(db_labels) as log:
            log.register_db("mysql/ecommerce_db", total_tables=12)
            log.info("mysql/ecommerce_db", "开始扫描")
            log.advance("mysql/ecommerce_db",
                        table="user", rows=500, findings=23)
            log.error("mysql/ecommerce_db", "连接断开")
    """

    def __init__(self, db_labels: list):
        self._labels = db_labels
        self._lock = threading.Lock()
        self._progress = None
        self._task_ids = {}
        self._counters = {}
        self._console = None

    # ── 上下文管理 ───────────────────────────────────────────────
    def __enter__(self):
        if _RICH_AVAILABLE:
            self._console = Console(stderr=False)
            # [关键] auto_refresh=False,不启动后台刷新线程
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=24),
                MofNCompleteColumn(),
                TextColumn(
                    "表 | 行[yellow]{task.fields[rows]}[/] | "
                    "命中[green]{task.fields[hits]}[/]"
                ),
                TimeElapsedColumn(),
                console=self._console,
                auto_refresh=False,
            )
            self._progress.start()
        return self

    def __exit__(self, *args):
        if self._progress:
            try:
                self._progress.refresh()
            except Exception:
                pass
            self._progress.stop()

    # ── 手动刷新封装 ─────────────────────────────────────────────
    def _refresh(self):
        if self._progress:
            try:
                self._progress.refresh()
            except Exception:
                pass

    # ── 注册数据库 ───────────────────────────────────────────────
    def register_db(self, label: str, total_tables: int):
        self._counters[label] = {"tables": 0, "rows": 0, "findings": 0}
        if self._progress:
            tid = self._progress.add_task(
                label,
                total=total_tables,
                rows=0,
                hits=0,
            )
            with self._lock:
                self._task_ids[label] = tid
            self._refresh()
        else:
            _plain_print(f"[START] {label} — {total_tables} 张表")

    # ── 推进 ─────────────────────────────────────────────────────
    def advance(self, label: str, table: str, rows: int, findings: int):
        with self._lock:
            c = self._counters.get(label, {})
            c["tables"] = c.get("tables", 0) + 1
            c["rows"] = c.get("rows", 0) + rows
            c["findings"] = c.get("findings", 0) + findings

        if self._progress and label in self._task_ids:
            self._progress.update(
                self._task_ids[label],
                advance=1,
                rows=f" {c['rows']:,}",
                hits=f" {c['findings']}",
                description=f"{label} [{table}]",
            )
            self._refresh()
        else:
            _plain_print(f"  [OK] {label}.{table} — {rows}行 {findings}命中")

    # ── 信息 ─────────────────────────────────────────────────────
    def info(self, label: str, msg: str):
        if self._progress:
            self._progress.console.print(f"[dim]{label}[/] {msg}")
            self._refresh()
        else:
            _plain_print(f"[INFO] {label} {msg}")

    def warning(self, label: str, msg: str):
        _file_logger.warning("%s | %s", label, msg)
        if self._progress:
            self._progress.console.print(f"[yellow][WARN][/] {label} — {msg}")
            self._refresh()
        else:
            _plain_print(f"[WARN] {label} {msg}")

    def error(self, label: str, msg: str):
        _file_logger.error("%s | %s", label, msg)
        if self._progress:
            self._progress.console.print(f"[red][ERROR][/] {label} — {msg}")
            self._refresh()
        else:
            _plain_print(f"[ERROR] {label} {msg}")

    # ── 摘要 ─────────────────────────────────────────────────────
    def summary(self):
        lines = []
        total_rows = total_hits = 0
        for label, c in self._counters.items():
            lines.append(
                f"  {label}: {c['tables']}表 / {c['rows']:,}行 / "
                f"{c['findings']}命中"
            )
            total_rows += c["rows"]
            total_hits += c["findings"]
        lines.append(f"  合计: {total_rows:,} 行 | {total_hits} 条发现")

        if self._progress:
            self._progress.console.rule("[bold]扫描摘要")
            for l in lines:
                self._progress.console.print(l)
            self._refresh()
        else:
            print("=" * 50)
            for l in lines:
                print(l)


def _plain_print(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{ts} {msg}", flush=True)
