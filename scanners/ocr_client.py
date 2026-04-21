"""
OCR 子进程客户端(v7: 2-slot 池化 + 稳态优先)。

目标运行环境:
  Intel i5-10400 / 16GB RAM / Win11 / CPU only (官方推荐)

池化演进:
  v5 1-slot × 0.5        → 爆池 + 单表吞吐不足
  v6 3-slot × 0.15       → 总占用 ~7.2GB 稳态 OK,但峰值+Docker+主进程贴满
                           16GB,第三轮(DB_WORKERS=2)仍频繁触发
                           "could not create a primitive" / OOM,slot 被永久停用
                           后 binary_blob FN 反弹到 86%。
  v7 2-slot × 0.20 【本版本】
    - 每 slot 内存 +33%(0.15→0.20),显著降低 rec padding 爆池概率
    - 总 fraction 0.40(<v6 的 0.45)给 OS/Docker/主进程留更多余量
    - slot 数与 DB_WORKERS=2 匹配:每个 DB 扫描线程一个 slot,
      BLOB 表的 dispatch 滑窗 = 2 × 2 = 4 刚好够填充 2 slot
    - 与 v6 3×0.15 吞吐理论上接近,但稳定性大幅提升(核心目标:别永久停用)

参数选择:
  - OCR_POOL_SIZE = 2
  - PER_IMAGE_TIMEOUT_SEC = 25s:单图稳态推理 ~1-2s,25s 是熔断兜底
  - SPAWN_TIMEOUT_SEC = 60s:首次加载 PaddleOCR v4 三个模型需要 20-40s
  - MAX_CONSEC_FAIL = 4:爆池后更早触发 kill+respawn
  - MAX_RESTART_CYCLES = 5:放宽硬熔断阈值(v6=3),宁可多重启,不要永久停用
    —— v6 经验:slot 一旦永久停用,BLOB 吞吐腰斩,直接掉到 86% FN

slot 级别的失败(连续 fail、重启 cycle)互不影响,slot 被永久停用后
整个 pool 仍可用;当所有 slot 都停用时 pool 整体 disabled。

env 硬约束(向子进程透传):
  FLAGS_fraction_of_cpu_memory_to_use=0.20
  由本文件 _spawn 显式传入,不依赖 main.py 的 setdefault。
"""
import os
import sys
import threading
import subprocess
import atexit
import queue

OCR_POOL_SIZE = 2               # 并行 worker 数;16GB 机上 2×0.20 fraction 合计 ~6.4GB
PER_IMAGE_TIMEOUT_SEC = 25      # 单图稳态推理超时
SPAWN_TIMEOUT_SEC = 60          # 首次/重建引擎加载超时(三模型 ~30s)
MAX_CONSEC_FAIL = 4             # 连续失败触发 kill+respawn 的阈值
MAX_RESTART_CYCLES = 5          # v6=3 太严,slot 永久停用会腰斩 BLOB 吞吐
RESTART_COOLDOWN_SEC = 3        # 每次重启前冷却,避免狂 spawn
WORKER_MODULE = "scanners.ocr_worker"

# 子进程内存上限(两个加一起 ~6.4GB,给 OS/Python/Docker 留 ~9.6GB)
# Why: v6 的 3 × 0.15 单 slot 内存太紧(rec 单行 padding 需要约 2GB,
#   0.15 对应 2.4GB 几乎贴边),峰值时触发 OOM/primitive 失败。
#   v7 降到 2 slot 换更大的单 slot 内存(0.20 对应 3.2GB),
#   rec padding 有富余空间,分配池碎片也不容易撞顶。
_WORKER_ENV_OVERRIDES = {
    "FLAGS_fraction_of_cpu_memory_to_use": "0.20",
}


class _OCRSlot:
    """单个 OCR worker 子进程 + 它的状态机。"""

    def __init__(self, slot_id: int):
        self.slot_id = slot_id
        self._proc = None
        self._lock = threading.Lock()
        self._consec_fail = 0
        self._disabled = False
        self._restart_cycles = 0
        self._just_spawned = False

    def _spawn(self):
        env = {**os.environ, **_WORKER_ENV_OVERRIDES}
        self._proc = subprocess.Popen(
            [sys.executable, "-u", "-m", WORKER_MODULE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            bufsize=0,
            cwd=os.getcwd(),
            env=env,
            shell=False,
        )
        self._just_spawned = True

    def _kill_locked(self):
        if self._proc is None:
            return
        try:
            if self._proc.poll() is None:
                self._proc.kill()
                try:
                    self._proc.wait(timeout=3)
                except Exception:
                    pass
        except Exception:
            pass
        self._proc = None

    def _ensure_alive_locked(self):
        if self._proc is not None and self._proc.poll() is None:
            return
        self._spawn()

    def _request(self, image_bytes: bytes):
        """调用方已持有 self._lock。"""
        try:
            self._ensure_alive_locked()
        except Exception as e:
            print(f"[OCR#{self.slot_id}] 子进程启动失败: {e}", flush=True)
            return None

        timeout = SPAWN_TIMEOUT_SEC if self._just_spawned else PER_IMAGE_TIMEOUT_SEC
        self._just_spawned = False

        proc = self._proc
        try:
            header = len(image_bytes).to_bytes(4, "big")
            proc.stdin.write(header)
            proc.stdin.write(image_bytes)
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            print(f"[OCR#{self.slot_id}] 写入子进程失败(疑似 crash): {e}", flush=True)
            self._kill_locked()
            return None

        holder = {"text": None, "error": None}

        def _reader():
            try:
                hdr = proc.stdout.read(4)
                if not hdr or len(hdr) != 4:
                    holder["error"] = "short header (worker exited)"
                    return
                n = int.from_bytes(hdr, "big")
                if n == 0:
                    holder["text"] = ""
                    return
                buf = bytearray()
                while len(buf) < n:
                    chunk = proc.stdout.read(n - len(buf))
                    if not chunk:
                        holder["error"] = "short body"
                        return
                    buf.extend(chunk)
                holder["text"] = bytes(buf).decode("utf-8", errors="replace")
            except Exception as e:
                holder["error"] = str(e)

        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            print(f"[OCR#{self.slot_id}] 等待响应超时 {timeout}s,杀掉子进程", flush=True)
            self._kill_locked()
            return None

        if holder["error"]:
            print(f"[OCR#{self.slot_id}] 读取响应失败: {holder['error']}", flush=True)
            self._kill_locked()
            return None

        return holder["text"]

    def get_text(self, image_bytes: bytes):
        """slot 级入口。永久停用或本次失败时返回 None。"""
        if self._disabled:
            return None

        with self._lock:
            text = self._request(image_bytes)

        if text is None:
            self._consec_fail += 1
            if self._consec_fail >= MAX_CONSEC_FAIL:
                with self._lock:
                    self._kill_locked()
                self._restart_cycles += 1
                if self._restart_cycles >= MAX_RESTART_CYCLES:
                    print(
                        f"[OCR#{self.slot_id}] 累计 {self._restart_cycles} 轮熔断,"
                        f"slot 永久停用",
                        flush=True,
                    )
                    self._disabled = True
                else:
                    print(
                        f"[OCR#{self.slot_id}] 连续失败 {self._consec_fail} 次,"
                        f"第 {self._restart_cycles} 轮重启中,冷却 {RESTART_COOLDOWN_SEC}s",
                        flush=True,
                    )
                    import time as _t
                    _t.sleep(RESTART_COOLDOWN_SEC)
                    self._consec_fail = 0
        else:
            self._consec_fail = 0

        return text

    def shutdown(self):
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                try:
                    self._proc.stdin.close()
                except Exception:
                    pass
                try:
                    self._proc.wait(timeout=5)
                except Exception:
                    self._kill_locked()
            self._proc = None


class _OCRPool:
    """
    OCR_POOL_SIZE 个 _OCRSlot 组成的池。

    - 空闲 slot 放在 _free 队列里;get_text 取一个用完放回。
    - slot 在本次请求中被判定永久停用 → 不放回队列(其它线程不会再拿到)。
    - 所有 slot 都停用 → pool.disabled 为 True,对外等同 OCR 不可用。
    """

    def __init__(self, size: int):
        self.size = size
        self._slots = [_OCRSlot(i) for i in range(size)]
        self._free = queue.Queue()
        for s in self._slots:
            self._free.put(s)

    @property
    def disabled(self) -> bool:
        return all(s._disabled for s in self._slots)

    def get_text(self, image_bytes: bytes):
        if self.disabled:
            return None
        if not image_bytes:
            return None

        slot = None
        # Why: queue.get 用 5s 超时是为了在所有 slot 同时被停用时不死锁。
        # 正常情况下池有空 slot 时几乎零等待。
        while slot is None:
            try:
                candidate = self._free.get(timeout=5)
            except queue.Empty:
                if self.disabled:
                    return None
                continue
            if candidate._disabled:
                # 被其他线程刚停用,继续找下一个
                continue
            slot = candidate

        try:
            return slot.get_text(image_bytes)
        finally:
            if not slot._disabled:
                self._free.put(slot)

    def shutdown(self):
        for s in self._slots:
            s.shutdown()


_pool = _OCRPool(OCR_POOL_SIZE)


def get_ocr_text(image_bytes):
    if isinstance(image_bytes, memoryview):
        image_bytes = bytes(image_bytes)
    if isinstance(image_bytes, bytearray):
        image_bytes = bytes(image_bytes)
    if not isinstance(image_bytes, bytes):
        return None
    return _pool.get_text(image_bytes)


def shutdown_ocr():
    _pool.shutdown()


def ocr_disabled() -> bool:
    return _pool.disabled


atexit.register(shutdown_ocr)
