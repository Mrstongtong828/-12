import os

# [OCR 稳定性] 必须在 numpy/cv2/paddle 任何 import 之前设置——OMP/MKL 线程数
# 由这些 C 扩展在 import 期一次性锁定，后改无效。
# Windows + Python 3.11 上 PaddleOCR 的 oneDNN 后端会抛
# "could not create a primitive"，并在多线程/多张图连跑时触发段错误。
# 根因是 OMP 线程竞争，pin 到 1 线程即稳定。
os.environ.setdefault("FLAGS_use_mkldnn", "0")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
# [OCR 内存] 让 Paddle 立刻回收临时 tensor，不在 arena 里堆积。
os.environ.setdefault("FLAGS_eager_delete_tensor_gb", "0")
os.environ.setdefault("FLAGS_allocator_strategy", "auto_growth")
# [比赛机 i5-10400/16GB] Paddle 占比封顶 ~4GB，给 Python/正则 /DB 驱动留出余量。
os.environ.setdefault("FLAGS_fraction_of_cpu_memory_to_use", "0.25")

import re
import gc
import numpy as np
from core.patterns import extract_sensitive_from_value
from core.config import SENSITIVE_LEVEL_MAP
from core.task_queue import ai_inference_slot

DET_MODEL_DIR = "./models/paddleocr/ch_PP-OCRv4_det_infer"
REC_MODEL_DIR = "./models/paddleocr/ch_PP-OCRv4_rec_infer"
CLS_MODEL_DIR = "./models/paddleocr/ch_ppocr_mobile_v2.0_cls_infer"

_ocr_engine = None

# [OCR 内存] Paddle inference 有内存泄漏：连续跑 ~30 张图后 numpy 数组分配会
# 失败（Unable to allocate X MiB）并连带段错误。每 N 次调用销毁引擎并强制 gc，
# 释放 Paddle arena allocator 持有的临时 tensor。
# [比赛机 16GB] 每 OCR_RESET_EVERY 次调用销毁引擎并 gc，释放 Paddle 中间 tensor。
# 16GB 下 30 比较合适；低内存机（≤8GB）降到 5 更稳。
OCR_RESET_EVERY = 30
_ocr_call_count = 0

OCR_CORRECTION_MAP = {
    'O': '0', 'o': '0',
    'I': '1', 'l': '1',
    'S': '5',
    'B': '8',
    'Z': '2',
    'G': '6',
    'T': '7',
}

_DIGIT_LIKE = re.compile(r"[0-9OoIlSBZGT]{6,}")
_NUM_CANDIDATE = re.compile(r"\d{11,}")


def get_ocr_engine():
    global _ocr_engine
    if _ocr_engine is None:
        from paddleocr import PaddleOCR
        _ocr_engine = PaddleOCR(
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
    return _ocr_engine


def correct_ocr_text(text: str) -> str:
    def _correct_segment(m):
        seg = m.group()
        return "".join(OCR_CORRECTION_MAP.get(c, c) for c in seg)
    return _DIGIT_LIKE.sub(_correct_segment, text)


def extract_number_candidates(text: str) -> list:
    return _NUM_CANDIDATE.findall(text)


# [OCR 内存] 图像过大时降采样到 MAX_OCR_SIDE，减轻 Paddle 中间 tensor 压力。
# 实测 800 对身份证/银行卡/短文本足够，对 Chinese 姓名召回无负面影响。
MAX_OCR_SIDE = 800


def _decode_image(blob_bytes: bytes):
    img = None
    try:
        import cv2
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
    # 降采样
    h, w = img.shape[:2]
    long_side = max(h, w)
    if long_side > MAX_OCR_SIDE:
        import cv2
        scale = MAX_OCR_SIDE / long_side
        img = cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
    return img


def _make_finding(db_type, db_name, table_name, field_col_name,
                  record_id, sensitive_type, extracted_value):
    level = SENSITIVE_LEVEL_MAP.get(sensitive_type, "L3")
    return {
        "db_type": db_type,
        "db_name": db_name,
        "table_name": table_name,
        "field_name": field_col_name,
        "record_id": record_id,
        "data_form": "binary_blob",
        "sensitive_type": sensitive_type,
        "sensitive_level": level,
        "extracted_value": extracted_value,
    }


def scan_blob_field(blob_bytes, record_id, table_name, field_col_name, db_type, db_name):
    if not blob_bytes:
        return []

    if isinstance(blob_bytes, memoryview):
        blob_bytes = bytes(blob_bytes)

    # 新增：处理 \x 前缀 hex 字符串（psycopg2 BYTEA 某些驱动版本的返回格式）
    if isinstance(blob_bytes, str):
        s = blob_bytes.strip()
        if s.startswith(r'\x') and len(s) > 4:
            try:
                blob_bytes = bytes.fromhex(s[2:])
            except ValueError:
                return []
        else:
            return []

    img = _decode_image(blob_bytes)
    if img is None:
        return []

    # [OCR 稳定性 + 内存] 每 OCR_RESET_EVERY 次调用销毁引擎并 gc，释放 Paddle
    # 持有的中间 tensor；偶发 "could not create a primitive" 也重建重试一次。
    global _ocr_engine, _ocr_call_count
    if _ocr_call_count >= OCR_RESET_EVERY:
        _ocr_engine = None
        _ocr_call_count = 0
        gc.collect()

    result = None
    last_err = None
    for attempt in range(2):
        try:
            ocr = get_ocr_engine()
            with ai_inference_slot("ocr"):
                result = ocr.ocr(img, cls=True)
            _ocr_call_count += 1
            break
        except Exception as e:
            last_err = e
            _ocr_engine = None
            _ocr_call_count = 0
            gc.collect()
    if result is None:
        print(f"[ERROR] OCR失败 {table_name}.{field_col_name} record={record_id}: {last_err}")
        return []

    if not result or not result[0]:
        return []

    lines = []
    for line in result[0]:
        if line and len(line) >= 2 and line[1]:
            text, conf = line[1][0], line[1][1]
            if conf > 0.5:
                lines.append(text)

    full_text = " ".join(lines)
    corrected = correct_ocr_text(full_text)

    findings = []
    seen = set()

    # [B3] 同时扫描原始 OCR 文本和纠错文本，取并集；纠错文本主要提升数字类型的召回
    for scan_text in (full_text, corrected):
        if not scan_text:
            continue
        for stype, val in extract_sensitive_from_value(scan_text):
            key = (stype, val)
            if key not in seen:
                seen.add(key)
                findings.append(_make_finding(
                    db_type, db_name, table_name, field_col_name,
                    record_id, stype, val,
                ))
    return findings
