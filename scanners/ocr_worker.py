"""
OCR 子进程入口。主进程通过 stdin/stdout 二进制流与之通信。

协议(长度前缀):
  请求  :  4B 大端长度 + 原始图片字节
  响应  :  4B 大端长度 + UTF-8 文本(长度 0 = 本张无文字)
  关闭  :  主进程关 stdin → 本进程 read 返回空 → 正常退出
  熔断  :  连续 CONSEC_FAIL_EXIT 次内部失败或累计 TOTAL_FAIL_EXIT 次,
          子进程不回响应直接 sys.exit,让主进程读 EOF 视为失败并累加熔断计数。

v2 稳定性改动(基于 diff_report 发现 OCR 大量内存分配失败):
  - MAX_OCR_SIDE: 640 → 512 (再砍 40% 像素)
  - RESET_EVERY: 8 → 4 (更频繁重建引擎,避免内存池碎片化)
  - 大图增加第二道缩放闸: 长边 > 1024 时先粗缩到 768 再精缩
  - 每次推理前强制 gc,降低峰值占用
  - 失败后立即 release 引擎并 gc,不等下一轮
  - FLAGS_fraction_of_cpu_memory_to_use 0.4 → 0.3 (更保守)
"""
import os
import sys

# ── 必须最早设置 ─────────────────────────────────────────────────
os.environ.setdefault("FLAGS_use_mkldnn", "0")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("FLAGS_eager_delete_tensor_gb", "0")
os.environ.setdefault("FLAGS_allocator_strategy", "auto_growth")
# [v2] 0.4 → 0.3, 给 numpy / cv2 留更多余量, 减少 memory_object 创建失败
os.environ.setdefault("FLAGS_fraction_of_cpu_memory_to_use", "0.3")
# [v2] 禁用 Paddle 的 memory reuse 优化,防止内存池碎片累积
os.environ.setdefault("FLAGS_memory_fraction_of_eager_deletion", "1.0")

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=False)
    except Exception:
        pass


DET_MODEL_DIR = "./models/paddleocr/ch_PP-OCRv4_det_infer"
REC_MODEL_DIR = "./models/paddleocr/ch_PP-OCRv4_rec_infer"
CLS_MODEL_DIR = "./models/paddleocr/ch_ppocr_mobile_v2.0_cls_infer"

# [v2] 640 → 512, 再砍 40% 像素内存占用
MAX_OCR_SIDE = 512
MIN_OCR_SIDE = 32
# [v2] 大图预缩放阈值: 长边 > 此值先粗缩到 768 再精缩到 MAX_OCR_SIDE
# 一步到位 cv2.resize 对 3000px 原图会瞬间分配 ~27MB,分两步降峰值
PRE_SCALE_THRESHOLD = 1024
PRE_SCALE_TARGET = 768

# worker 内部熔断阈值
CONSEC_FAIL_EXIT = 5
TOTAL_FAIL_EXIT = 15

# [v2] 8 → 4, 更频繁重建引擎, 对抗内存池碎片
RESET_EVERY = 4


def _read_exact(stream, n: int):
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _make_ocr():
    from paddleocr import PaddleOCR
    return PaddleOCR(
        use_angle_cls=True, lang="ch",
        use_gpu=False, enable_mkldnn=False, cpu_threads=1,
        det_model_dir=DET_MODEL_DIR,
        rec_model_dir=REC_MODEL_DIR,
        cls_model_dir=CLS_MODEL_DIR,
        show_log=False,
    )


def _decode_image(blob_bytes: bytes):
    import numpy as np
    try:
        import cv2
    except Exception:
        cv2 = None

    img = None
    if cv2 is not None:
        try:
            arr = np.frombuffer(blob_bytes, np.uint8)
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        except Exception:
            pass

    if img is None:
        try:
            import io
            from PIL import Image
            img_pil = Image.open(io.BytesIO(blob_bytes)).convert("RGB")
            img = np.array(img_pil)[:, :, ::-1]
        except Exception:
            return None

    if img is None:
        return None

    h, w = img.shape[:2]
    if min(h, w) < MIN_OCR_SIDE:
        return None

    long_side = max(h, w)

    # [v2] 两步缩放: 超大图先粗缩再精缩,降分配峰值
    if long_side > PRE_SCALE_THRESHOLD and cv2 is not None:
        try:
            scale1 = PRE_SCALE_TARGET / long_side
            new_w = max(1, int(w * scale1))
            new_h = max(1, int(h * scale1))
            img = cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_AREA)
            h, w = img.shape[:2]
            long_side = max(h, w)
        except Exception:
            pass

    # 精缩到 MAX_OCR_SIDE
    if long_side > MAX_OCR_SIDE and cv2 is not None:
        try:
            scale = MAX_OCR_SIDE / long_side
            new_w = max(1, int(w * scale))
            new_h = max(1, int(h * scale))
            img = cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_AREA)
        except Exception:
            pass
    return img


def _ocr_once(ocr_engine, img_bytes: bytes) -> str:
    """
    单次 OCR。
      返回字符串 → 成功(空串表示无文字)
      抛异常    → OCR 内部失败,由调用方捕获并累加失败计数
    """
    img = _decode_image(img_bytes)
    if img is None:
        return ""
    result = ocr_engine.ocr(img, cls=True)
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
    consec_fail = 0
    total_fail = 0

    while True:
        header = _read_exact(stdin, 4)
        if header is None:
            break
        n = int.from_bytes(header, "big")
        if n == 0:
            _write_response(stdout, "")
            continue
        if n > 100 * 1024 * 1024:
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

        if ocr_engine is None:
            try:
                ocr_engine = _make_ocr()
            except Exception as e:
                sys.stderr.write(f"[ocr_worker] engine init failed: {e}\n")
                sys.exit(2)

        # [v2] 每次推理前主动 gc,降低峰值占用
        if call_count > 0 and call_count % 2 == 0:
            gc.collect()

        # ── 实际推理 ─────────────────────────────────────────────
        text = ""
        try:
            text = _ocr_once(ocr_engine, img_bytes)
            consec_fail = 0
        except Exception as e:
            sys.stderr.write(f"[ocr_worker] ocr call failed: {e}\n")
            consec_fail += 1
            total_fail += 1
            # 失败后立刻销毁引擎,下一次重新加载
            ocr_engine = None
            call_count = 0
            try:
                gc.collect()
            except Exception:
                pass

            if consec_fail >= CONSEC_FAIL_EXIT or total_fail >= TOTAL_FAIL_EXIT:
                sys.stderr.write(
                    f"[ocr_worker] too many failures "
                    f"(consec={consec_fail}, total={total_fail}), exiting\n"
                )
                sys.exit(3)

        call_count += 1
        _write_response(stdout, text)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        pass
