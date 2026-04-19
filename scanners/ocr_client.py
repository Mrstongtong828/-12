"""
OCR 子进程客户端。
改动要点:
  - PER_IMAGE_TIMEOUT_SEC 45→25
  - MAX_CONSEC_FAIL 3→2, 熔断更早触发
  - 修 BUG: 每次 re-spawn 后首次调用使用 SPAWN_TIMEOUT_SEC,而不是被
    _first_call 这个"整个 client 生命周期里只用一次"的标记压回 25s
"""
import os
import sys
import threading
import subprocess
import atexit

PER_IMAGE_TIMEOUT_SEC = 25      # 从 45 下调
SPAWN_TIMEOUT_SEC = 60
MAX_CONSEC_FAIL = 2             # 从 3 下调
WORKER_MODULE = "scanners.ocr_worker"


class _OCRClient:
    def __init__(self):
        self._proc = None
        self._lock = threading.Lock()
        self._consec_fail = 0
        self._disabled = False
        # [改] 不再用 _first_call,改为"本次 request 是否刚 spawn"标记
        self._just_spawned = False

    def _spawn(self):
        self._proc = subprocess.Popen(
            [sys.executable, "-u", "-m", WORKER_MODULE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            bufsize=0,
            cwd=os.getcwd(),
            shell=False,
        )
        self._just_spawned = True   # 新 worker 第一次调用需要长超时

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
        with self._lock:
            try:
                self._ensure_alive_locked()
            except Exception as e:
                print(f"[OCR] 子进程启动失败: {e}", flush=True)
                return None

            # [改] 根据是否刚 spawn 动态选择超时
            timeout = SPAWN_TIMEOUT_SEC if self._just_spawned else PER_IMAGE_TIMEOUT_SEC
            self._just_spawned = False

            proc = self._proc
            try:
                header = len(image_bytes).to_bytes(4, "big")
                proc.stdin.write(header)
                proc.stdin.write(image_bytes)
                proc.stdin.flush()
            except (BrokenPipeError, OSError) as e:
                print(f"[OCR] 写入子进程失败(疑似 crash): {e}", flush=True)
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
                print(f"[OCR] 等待响应超时 {timeout}s,杀掉子进程", flush=True)
                self._kill_locked()
                return None

            if holder["error"]:
                print(f"[OCR] 读取响应失败: {holder['error']}", flush=True)
                self._kill_locked()
                return None

            return holder["text"]

    def get_text(self, image_bytes: bytes):
        if self._disabled:
            return None
        if not image_bytes:
            return None

        text = self._request(image_bytes)

        if text is None:
            self._consec_fail += 1
            if self._consec_fail >= MAX_CONSEC_FAIL:
                print(
                    f"[OCR] 连续失败 {self._consec_fail} 次,"
                    f"本轮禁用 OCR(剩余图片按 0 命中处理)",
                    flush=True,
                )
                self._disabled = True
                with self._lock:
                    self._kill_locked()
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


_client = _OCRClient()


def get_ocr_text(image_bytes):
    if isinstance(image_bytes, memoryview):
        image_bytes = bytes(image_bytes)
    if isinstance(image_bytes, bytearray):
        image_bytes = bytes(image_bytes)
    if not isinstance(image_bytes, bytes):
        return None
    return _client.get_text(image_bytes)


def shutdown_ocr():
    _client.shutdown()


def ocr_disabled() -> bool:
    return _client._disabled


atexit.register(shutdown_ocr)
