"""
OCR 子进程入口。主进程通过 stdin/stdout 二进制流与之通信。

协议(长度前缀):
  请求  :  4B 大端长度 + 原始图片字节
  响应  :  4B 大端长度 + UTF-8 文本(长度 0 = 本张识别失败)
  关闭  :  主进程关 stdin → 本进程 read 返回空 → 正常退出

用法:
  python -u -m scanners.ocr_worker      # -u 必须,禁用 stdout 缓冲

为什么要子进程:
  PaddleOCR 2.7 在 Windows + Python 3.11 + CPU 下会偶发段错误
  (oneDNN primitive 创建失败 + OMP 线程竞争),Python try/except 接不住。
  放到子进程里死了就死了,主进程 BrokenPipeError → 重建即可。
"""
import os
import sys

# ── 必须最早设置 ─────────────────────────────────────────────────
# numpy/cv2/paddle 的 C 扩展在 import 期一次性读取这些环境变量,
# 之后改无效。子进程启动时第一件事就是 pin 线程数。
os.environ.setdefault("FLAGS_use_mkldnn", "0")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("FLAGS_eager_delete_tensor_gb", "0")
os.environ.setdefault("FLAGS_allocator_strategy", "auto_growth")
os.environ.setdefault("FLAGS_fraction_of_cpu_memory_to_use", "0.25")

# 关掉 stdout 的行缓冲,避免二进制协议错位
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=False)
    except Exception:
        pass


DET_MODEL_DIR = "./models/paddleocr/ch_PP-OCRv4_det_infer"
REC_MODEL_DIR = "./models/paddleocr/ch_PP-OCRv4_rec_infer"
CLS_MODEL_DIR = "./models/paddleocr/ch_ppocr_mobile_v2.0_cls_infer"
MAX_OCR_SIDE = 800


def _read_exact(stream, n: int):
    """从 stream 精确读 n 字节,EOF 返回 None。"""
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _make_ocr():
    """懒加载 OCR 引擎。失败抛异常,由外层统一处理。"""
    from paddleocr import PaddleOCR
    return PaddleOCR(
        use_angle_cls=True,
        lang="ch",
        use_gpu=False,
        enable_mkldnn=False,
        cpu_threads=1,
        det_model_dir=DET_MODEL_DIR,
        rec_model_dir=REC_MODEL_DIR,
        cls_model_dir=CLS_MODEL_DIR,
        show_log=False,
    )


def _decode_image(blob_bytes: bytes):
    """bytes → ndarray(HWC, BGR)。cv2 优先,PIL 兜底。失败返 None。"""
    img = None
    try:
        import numpy as np
        import cv2
        arr = np.frombuffer(blob_bytes, np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    except Exception:
        pass
    if img is None:
        try:
            import io
            import numpy as np
            from PIL import Image
            img_pil = Image.open(io.BytesIO(blob_bytes)).convert("RGB")
            img = np.array(img_pil)[:, :, ::-1]
        except Exception:
            return None
    if img is None:
        return None

    h, w = img.shape[:2]
    long_side = max(h, w)
    if long_side > MAX_OCR_SIDE:
        try:
            import cv2
            scale = MAX_OCR_SIDE / long_side
            img = cv2.resize(img, (int(w * scale), int(h * scale)),
                             interpolation=cv2.INTER_AREA)
        except Exception:
            pass
    return img


def _ocr_once(ocr_engine, img_bytes: bytes) -> str:
    """单次 OCR,失败返空串(不抛)。"""
    img = _decode_image(img_bytes)
    if img is None:
        return ""
    try:
        result = ocr_engine.ocr(img, cls=True)
    except Exception as e:
        sys.stderr.write(f"[ocr_worker] ocr call failed: {e}\n")
        return ""
    if not result or not result[0]:
        return ""
    lines = []
    for line in result[0]:
        if line and len(line) >= 2 and line[1]:
            text, conf = line[1][0], line[1][1]
            if conf > 0.5:
                lines.append(text)
    return " ".join(lines)


def _write_response(stdout, text: str):
    data = text.encode("utf-8", errors="replace")
    stdout.write(len(data).to_bytes(4, "big"))
    if data:
        stdout.write(data)
    stdout.flush()


def main():
    import gc

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    ocr_engine = None
    call_count = 0
    RESET_EVERY = 30   # 每 30 张重建一次引擎,释放 Paddle arena

    while True:
        header = _read_exact(stdin, 4)
        if header is None:
            break
        n = int.from_bytes(header, "big")
        if n == 0:
            _write_response(stdout, "")
            continue
        if n > 100 * 1024 * 1024:   # 单张硬上限 100MB,防跑飞
            # 丢弃这批字节后回空
            _ = _read_exact(stdin, n)
            _write_response(stdout, "")
            continue

        img_bytes = _read_exact(stdin, n)
        if img_bytes is None:
            break

        # 周期性重建引擎
        if ocr_engine is not None and call_count >= RESET_EVERY:
            ocr_engine = None
            call_count = 0
            gc.collect()

        # 懒加载;加载失败直接退出,让主进程知道 worker 不可用
        if ocr_engine is None:
            try:
                ocr_engine = _make_ocr()
            except Exception as e:
                sys.stderr.write(f"[ocr_worker] engine init failed: {e}\n")
                sys.exit(2)

        text = _ocr_once(ocr_engine, img_bytes)
        call_count += 1
        _write_response(stdout, text)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # 父进程先关了 stdin/stdout,正常退出
        pass
    except KeyboardInterrupt:
        pass
