"""
OCR 子进程客户端。

职责:
  - 维护一个长驻 ocr_worker 子进程
  - 按长度前缀协议发送图片、接收 OCR 文本
  - 读 / 写超时用后台线程 + join 超时实现(跨平台)
  - 子进程崩溃(BrokenPipe / 短读)时自动重启
  - 熔断:连续 MAX_CONSEC_FAIL 次失败后,本轮扫描禁用 OCR
           (避免对每张图都重建一次 Paddle 白白浪费 30min 时间预算)

对外 API(和旧 blob.py 兼容):
  get_ocr_text(image_bytes) -> str | None
    返回识别文本;None 表示失败(被熔断或子进程挂了)

注意:
  import 此模块不会启动子进程。第一次调用 get_ocr_text 才会 spawn。
  程序结束前应调用 shutdown_ocr() 主动关闭 worker。
"""
import os
import sys
import threading
import subprocess
import atexit

# ── 调优参数 ─────────────────────────────────────────────────────
PER_IMAGE_TIMEOUT_SEC = 45      # 单张 OCR 最长等待时间
SPAWN_TIMEOUT_SEC = 60          # 首次启动(含模型加载)最长等待时间
MAX_CONSEC_FAIL = 3             # 连续失败 N 次触发熔断
WORKER_MODULE = "scanners.ocr_worker"


class _OCRClient:
    def __init__(self):
        self._proc = None
        self._lock = threading.Lock()
        self._consec_fail = 0
        self._disabled = False       # 熔断后置 True,本轮不再重试
        self._first_call = True

    # ── 子进程管理 ───────────────────────────────────────────────
    def _spawn(self):
        """启动新 worker。失败抛异常。"""
        # bufsize=0: 主进程侧 stdin/stdout 无缓冲,二进制协议不会错位
        # -u       : 子进程侧 stdout 无缓冲
        self._proc = subprocess.Popen(
            [sys.executable, "-u", "-m", WORKER_MODULE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # stderr 不接,让子进程的错误信息直接输出到终端,便于观察
            stderr=None,
            bufsize=0,
            cwd=os.getcwd(),
            # Windows 下不开 shell
            shell=False,
        )

    def _kill_locked(self):
        """加锁状态下杀掉子进程。"""
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
        """加锁状态下确保 worker 存活,必要时重启。"""
        if self._proc is not None and self._proc.poll() is None:
            return
        self._spawn()

    # ── 单次请求(加锁) ─────────────────────────────────────────
    def _request(self, image_bytes: bytes, timeout: float):
        """
        发一张图,返回 OCR 文本。失败返 None(上层决定是否熔断)。
        """
        with self._lock:
            try:
                self._ensure_alive_locked()
            except Exception as e:
                print(f"[OCR] 子进程启动失败: {e}", flush=True)
                return None

            proc = self._proc

            # ── 发送 ─────────────────────────────────────────────
            try:
                header = len(image_bytes).to_bytes(4, "big")
                proc.stdin.write(header)
                proc.stdin.write(image_bytes)
                proc.stdin.flush()
            except (BrokenPipeError, OSError) as e:
                print(f"[OCR] 写入子进程失败(疑似 crash): {e}", flush=True)
                self._kill_locked()
                return None

            # ── 接收(子线程 + join 超时) ───────────────────────
            holder = {"text": None, "error": None}

            def _reader():
                try:
                    hdr = proc.stdout.read(4)
                    if not hdr or len(hdr) != 4:
                        holder["error"] = "short header"
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
                # 超时,worker 要么死锁要么太慢,杀掉
                print(f"[OCR] 等待响应超时 {timeout}s,杀掉子进程", flush=True)
                self._kill_locked()
                return None

            if holder["error"]:
                print(f"[OCR] 读取响应失败: {holder['error']}", flush=True)
                self._kill_locked()
                return None

            return holder["text"]

    # ── 对外接口 ─────────────────────────────────────────────────
    def get_text(self, image_bytes: bytes):
        if self._disabled:
            return None
        if not image_bytes:
            return None

        timeout = SPAWN_TIMEOUT_SEC if self._first_call else PER_IMAGE_TIMEOUT_SEC
        self._first_call = False

        text = self._request(image_bytes, timeout)

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


# ── 模块级单例 ───────────────────────────────────────────────────
_client = _OCRClient()


def get_ocr_text(image_bytes):
    """
    返回 OCR 识别结果字符串;失败或被熔断返 None。
    """
    if isinstance(image_bytes, memoryview):
        image_bytes = bytes(image_bytes)
    if isinstance(image_bytes, bytearray):
        image_bytes = bytes(image_bytes)
    if not isinstance(image_bytes, bytes):
        return None
    return _client.get_text(image_bytes)


def shutdown_ocr():
    """程序结束前调用,清理 worker。"""
    _client.shutdown()


def ocr_disabled() -> bool:
    """当前是否已被熔断。"""
    return _client._disabled


# 进程退出时兜底关闭子进程
atexit.register(shutdown_ocr)
