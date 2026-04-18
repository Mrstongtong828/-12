"""
终端可视化日志模块。

屏幕：用 rich 在底部显示 4 个数据库的扫描进度条。
文件：所有 WARNING/ERROR 写入 scan_error.log，不污染终端。
线程安全：rich.Progress 内部加锁，多线程直接调用 advance/update 即可。
"""
import logging
import threading
from datetime import datetime

try:
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn,
        BarColumn, MofNCompleteColumn, TimeElapsedColumn,
    )
    from rich.console import Console
    from rich.logging import RichHandler
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False

_LOG_FILE = "scan_error.log"

# ── 文件日志（始终启用）──────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(_LOG_FILE, encoding="utf-8")],
)
_file_logger = logging.getLogger("scan")


class ScanLogger:
    """
    用法（在 main.py 里）：

        with ScanLogger(db_labels) as log:
            log.register_db("mysql/ecommerce_db", total_tables=12)
            log.info("mysql/ecommerce_db", "开始扫描")
            log.advance("mysql/ecommerce_db", table="user", rows=500, findings=23)
            log.error("mysql/ecommerce_db", "连接断开")
    """

    def __init__(self, db_labels: list):
        self._labels = db_labels
        self._lock = threading.Lock()
        self._progress = None
        self._task_ids = {}   # label -> task_id
        self._counters = {}   # label -> {"tables": 0, "rows": 0, "findings": 0}
        self._console = None

    # ── 上下文管理器 ─────────────────────────────────────────────
    def __enter__(self):
        if _RICH_AVAILABLE:
            self._console = Console(stderr=False)
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=24),
                MofNCompleteColumn(),
                TextColumn("表 | 行[yellow]{task.fields[rows]}[/] | 命中[green]{task.fields[hits]}[/]"),
                TimeElapsedColumn(),
                console=self._console,
                refresh_per_second=4,
            )
            self._progress.start()
        return self

    def __exit__(self, *args):
        if self._progress:
            self._progress.stop()

    # ── 注册数据库进度条 ─────────────────────────────────────────
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
        else:
            _plain_print(f"[START] {label} — {total_tables} 张表")

    # ── 推进一张表 ───────────────────────────────────────────────
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
        else:
            _plain_print(f"  [OK] {label}.{table} — {rows}行 {findings}命中")

    # ── 普通信息（不写文件）──────────────────────────────────────
    def info(self, label: str, msg: str):
        if self._progress:
            self._progress.console.print(f"[dim]{label}[/] {msg}")
        else:
            _plain_print(f"[INFO] {label} {msg}")

    # ── 警告/错误（写文件 + 终端）────────────────────────────────
    def warning(self, label: str, msg: str):
        _file_logger.warning("%s | %s", label, msg)
        if self._progress:
            self._progress.console.print(f"[yellow][WARN][/] {label} — {msg}")
        else:
            _plain_print(f"[WARN] {label} {msg}")

    def error(self, label: str, msg: str):
        _file_logger.error("%s | %s", label, msg)
        if self._progress:
            self._progress.console.print(f"[red][ERROR][/] {label} — {msg}")
        else:
            _plain_print(f"[ERROR] {label} {msg}")

    # ── 全局摘要（扫描结束时调用）────────────────────────────────
    def summary(self):
        lines = []
        total_rows = total_hits = 0
        for label, c in self._counters.items():
            lines.append(
                f"  {label}: {c['tables']}表 / {c['rows']:,}行 / {c['findings']}命中"
            )
            total_rows += c["rows"]
            total_hits += c["findings"]
        lines.append(f"  合计: {total_rows:,} 行 | {total_hits} 条发现")

        if self._progress:
            self._progress.console.rule("[bold]扫描摘要")
            for l in lines:
                self._progress.console.print(l)
        else:
            print("=" * 50)
            for l in lines:
                print(l)


def _plain_print(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{ts} {msg}", flush=True)
