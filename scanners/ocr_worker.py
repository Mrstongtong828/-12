"""
OCR 子进程入口。主进程通过 stdin/stdout 二进制流与之通信。

目标运行环境:
  Intel i5-10400 / 16GB RAM / Win11 / CPU only (官方推荐)
  16GB 理论上够用,但实测 2026-04-21 run.log 出现 "could not create a primitive" /
  "could not create a memory object" / "Unable to allocate X MiB ... shape (6, *, 6625)",
  根因是 rec 默认 batch=6 把一张超宽印刷图的文本行 padding 后峰值内存爆表,
  所以本轮直接按官方低内存推荐压参数。

协议(长度前缀):
  请求  :  4B 大端长度 + 原始图片字节
  响应  :  4B 大端长度 + UTF-8 文本(长度 0 = 本张无文字)
  关闭  :  主进程关 stdin → 本进程 read 返回空 → 正常退出
  熔断  :  连续 CONSEC_FAIL_EXIT 次内部失败或累计 TOTAL_FAIL_EXIT 次,
          子进程不回响应直接 sys.exit,让主进程读 EOF 视为失败。

参数选择说明(v7 低内存 / CPU-only / 2-worker 池化档):
  - FLAGS_fraction_of_cpu_memory_to_use = 0.20 (每 worker ~3.2GB,两个合计 ~6.4GB)
    Why: v6 的 3 × 0.15 合计 0.45,与 Docker(MySQL+PG)+主进程峰值叠加后仍触发 OOM。
         v7 降到 2 slot、每 slot 给 0.20,单 slot 内存 +33%,rec padding 有富余,
         总占用 0.40 更宽松。
  - MAX_OCR_SIDE = 800 (v6=960,再压一档进一步削峰)
  - MAX_OCR_PIXELS = 800*800 (总像素硬顶,窄长条图也逃不掉)
  - EXTREME_ASPECT = 3.0 (宽高比超过这个,额外再压到 640 边长)
  - rec_batch_num = 1 (默认 6,一次只处理 1 行文本,峰值内存线性降)
  - RESET_EVERY = 6 (v6=8,主动重建周期再缩短,抑制分配池碎片长尾)
  - PRE_SCALE_THRESHOLD=1600 / PRE_SCALE_TARGET=1100 (v6=2000/1400,更早粗缩)

NOTE: 上面的 FLAGS 值由 ocr_client._spawn 通过 env 显式传入(硬覆盖),
      本文件里的 os.environ.setdefault 仅作 worker 单跑调试时的兜底。
"""
import os
import sys

# ── 必须最早设置(import paddle 之前) ────────────────────────────
# 关掉 oneDNN 与多线程 —— 低内存机型最关键的两刀
os.environ.setdefault("FLAGS_use_mkldnn", "0")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("FLAGS_eager_delete_tensor_gb", "0")
os.environ.setdefault("FLAGS_allocator_strategy", "auto_growth")
# 单 worker Paddle 分配池上限 —— v7 2-slot × 0.20 合计 ~6.4GB。
# ocr_client._spawn 会以 env 硬覆盖此值,这里的 setdefault 仅兜底。
os.environ.setdefault("FLAGS_fraction_of_cpu_memory_to_use", "0.20")

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=False)
    except Exception:
        pass


DET_MODEL_DIR = "./models/paddleocr/ch_PP-OCRv4_det_infer"
REC_MODEL_DIR = "./models/paddleocr/ch_PP-OCRv4_rec_infer"
CLS_MODEL_DIR = "./models/paddleocr/ch_ppocr_mobile_v2.0_cls_infer"

# 图片尺寸约束(v7)
# Why: v6(960 边长)在 3-slot × 0.15 下仍多次触发 primitive 创建失败。
# v7 做三件事:
#   1) MAX_OCR_SIDE 960→800(单张图 det+rec 峰值内存 -30%)
#   2) MAX_OCR_PIXELS 同步降到 800×800(方形巨图也走硬顶)
#   3) 宽高比 > 3 的图额外再压到 640(护照/身份证长条扫描件典型场景)
# 这个分辨率下中文印刷体仍然可识别,对身份证/银行卡数字几乎无损。
MAX_OCR_SIDE = 800
MIN_OCR_SIDE = 32
MAX_OCR_PIXELS = 800 * 800      # 约 64 万像素硬顶
EXTREME_ASPECT_RATIO = 3.0
EXTREME_ASPECT_MAX_SIDE = 640
# 超大图先粗缩,中间目标匹配新的 800 上限
PRE_SCALE_THRESHOLD = 1600
PRE_SCALE_TARGET = 1100

# worker 内部熔断阈值
CONSEC_FAIL_EXIT = 5
TOTAL_FAIL_EXIT = 15

# 引擎重建周期
# Why: v6=8 仍观察到 "retry after rebuild: ok" 多次出现,说明到第 8 张就已经
# 累积碎片。v7=6 让主动 rebuild 更早,单次重建成本 ~20-30s,但能彻底消除
# 长尾 primitive 失败,整体吞吐反而更稳。
RESET_EVERY = 6


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
    # 低内存关键参数(见文件头注释):
    #   rec_batch_num=1      —— 单行单打,消灭 (6, 54, 6625) 这类 batch padding 爆池
    #   det_limit_side_len   —— 显式固定检测前 resize 目标(和我们预处理对齐)
    #   det_limit_type="max" —— 以长边为准,和 _decode_image 一致
    #   det_db_score_mode    —— "fast" 比 "slow" 少一半后处理内存
    return PaddleOCR(
        use_angle_cls=True, lang="ch",
        use_gpu=False, enable_mkldnn=False, cpu_threads=1,
        rec_batch_num=1,
        det_limit_side_len=MAX_OCR_SIDE,
        det_limit_type="max",
        det_db_score_mode="fast",
        det_model_dir=DET_MODEL_DIR,
        rec_model_dir=REC_MODEL_DIR,
        cls_model_dir=CLS_MODEL_DIR,
        show_log=False,
    )


def _decode_image(blob_bytes: bytes):
    """解码图片字节 → numpy BGR 矩阵,同时做尺寸限制。"""
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
    # 太小的图直接跳过,多半是 icon/logo
    if min(h, w) < MIN_OCR_SIDE:
        return None

    def _pil_resize(arr, new_w, new_h):
        """cv2 不可用时的 PIL 兜底 resize,保证限制一定生效。"""
        try:
            from PIL import Image
            img_pil = Image.fromarray(arr[:, :, ::-1])  # BGR → RGB
            img_pil = img_pil.resize((new_w, new_h), Image.BILINEAR)
            return np.array(img_pil)[:, :, ::-1]
        except Exception:
            return arr

    def _resize_to(arr, new_w, new_h):
        if cv2 is not None:
            try:
                return cv2.resize(arr, (new_w, new_h), interpolation=cv2.INTER_AREA)
            except Exception:
                pass
        return _pil_resize(arr, new_w, new_h)

    # ① 超大图先粗缩一步,减小单次 resize 峰值
    long_side = max(h, w)
    if long_side > PRE_SCALE_THRESHOLD:
        scale1 = PRE_SCALE_TARGET / long_side
        new_w = max(1, int(w * scale1))
        new_h = max(1, int(h * scale1))
        img = _resize_to(img, new_w, new_h)
        h, w = img.shape[:2]
        long_side = max(h, w)

    # ② 极端宽高比:A4 扫描件横拍或长条合同,即便长边合规也会在 rec 端爆 batch,
    #    额外把长边压到 EXTREME_ASPECT_MAX_SIDE
    aspect = max(h, w) / max(1, min(h, w))
    target_long = EXTREME_ASPECT_MAX_SIDE if aspect > EXTREME_ASPECT_RATIO else MAX_OCR_SIDE
    if long_side > target_long:
        scale = target_long / long_side
        new_w = max(1, int(w * scale))
        new_h = max(1, int(h * scale))
        img = _resize_to(img, new_w, new_h)
        h, w = img.shape[:2]

    # ③ 总像素兜底:长边合规但短边还是很大的"方形巨图"也要压下去
    if h * w > MAX_OCR_PIXELS:
        scale = (MAX_OCR_PIXELS / (h * w)) ** 0.5
        new_w = max(1, int(w * scale))
        new_h = max(1, int(h * scale))
        img = _resize_to(img, new_w, new_h)

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
    # 卡面 ROI 矫正:提升 ID/银行卡/户籍页的字符清晰度。
    # 任何失败(含 import/运行异常)都保持原图,保五形态不回归。
    try:
        from scanners.card_roi import detect_and_warp
        img, _roi_tag = detect_and_warp(img)
    except Exception:
        pass
    result = ocr_engine.ocr(img, cls=True)
    if not result or not result[0]:
        return ""
    lines = []
    for line in result[0]:
        if line and len(line) >= 2 and line[1]:
            text, conf = line[1][0], line[1][1]
            # Why: 0.5 会把弱识别的数字行(糊掉的身份证/银行卡)整行丢弃,
            # 下游有 GB11643 校验位 + Luhn + 首位 3-9 把误报兜掉,所以可放宽。
            if conf > 0.3:
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

        text = ""
        try:
            text = _ocr_once(ocr_engine, img_bytes)
            consec_fail = 0
        except Exception as e:
            sys.stderr.write(f"[ocr_worker] ocr call failed: {e}\n")
            # Why: Paddle 分配池爆池后,销毁引擎重建一次就能拿到干净的池。
            # 之前直接返回空吞掉这张图 → binary_blob 大量 FN。
            ocr_engine = None
            call_count = 0
            try:
                gc.collect()
            except Exception:
                pass
            try:
                ocr_engine = _make_ocr()
                text = _ocr_once(ocr_engine, img_bytes)
                consec_fail = 0
                sys.stderr.write("[ocr_worker] retry after rebuild: ok\n")
            except Exception as e2:
                sys.stderr.write(f"[ocr_worker] retry also failed: {e2}\n")
                consec_fail += 1
                total_fail += 1
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
