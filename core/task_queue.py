"""
AI 推理资源管理器。

问题背景：
  4 个 DB 线程同时扫到图片表 → 同时触发 OCR → 4 个 PaddleOCR 实例并发推理
  → 赛场机器 16GB RAM 瞬间 OOM，程序崩溃。

解决方案：
  用 Semaphore 把"IO 密集型"和"CPU/内存密集型"任务分开限流：
    - DB 读取（IO 密集）：DB_WORKERS 线程并发，不受此限制
    - AI 推理（CPU 密集，高内存）：全局最多 AI_MAX_WORKERS 个槽位同时运行
      赛场硬件（i5-10400 / 16GB / 无 GPU）建议设为 1

  Wait queue 监控：记录线程获取槽位的平均等待时间，事后可判断 OCR
  是否真的成为瓶颈（等待时间 > 推理时间 = 主线程池需要再放大）。
"""
import threading
import time
from contextlib import contextmanager

# 赛场硬件：i5-10400 / 16GB RAM / 无 GPU，保守设为 1
AI_MAX_WORKERS = 1

_ai_semaphore = threading.Semaphore(AI_MAX_WORKERS)
_ai_lock = threading.Lock()
_active_ai_count = 0
_total_ai_calls = 0
_total_ai_time = 0.0
_total_wait_time = 0.0   # [#14] 等待槽位的总时间，判断并发是否有效


@contextmanager
def ai_inference_slot(task_name: str = "ai"):
    """
    上下文管理器：获取 AI 推理槽位后执行，结束后自动释放。

    用法：
        with ai_inference_slot("ocr"):
            result = ocr.ocr(img)
    """
    global _active_ai_count, _total_ai_calls, _total_ai_time, _total_wait_time

    t_wait_start = time.time()
    _ai_semaphore.acquire()
    t_exec_start = time.time()
    wait_elapsed = t_exec_start - t_wait_start

    with _ai_lock:
        _active_ai_count += 1
        _total_ai_calls += 1
        _total_wait_time += wait_elapsed

    try:
        yield
    finally:
        exec_elapsed = time.time() - t_exec_start
        with _ai_lock:
            _active_ai_count -= 1
            _total_ai_time += exec_elapsed
        _ai_semaphore.release()


def ai_stats() -> dict:
    """返回 AI 推理统计信息，用于性能报告。"""
    with _ai_lock:
        avg_wait = _total_wait_time / _total_ai_calls if _total_ai_calls else 0.0
        avg_exec = _total_ai_time / _total_ai_calls if _total_ai_calls else 0.0
        return {
            "total_calls": _total_ai_calls,
            "total_time_s": round(_total_ai_time, 2),
            "avg_time_s": round(avg_exec, 2),
            # [#14] 新增：平均等待时间。如果 avg_wait > avg_time，
            # 说明 OCR 队列排队严重，把 DB_WORKERS 再开大效果有限（已被 OCR 卡住）
            "total_wait_s": round(_total_wait_time, 2),
            "avg_wait_s": round(avg_wait, 2),
            "active_now": _active_ai_count,
            "max_concurrent": AI_MAX_WORKERS,
        }
