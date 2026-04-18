import re
import numpy as np
from core.patterns import extract_sensitive_from_value
from core.config import SENSITIVE_LEVEL_MAP
from core.task_queue import ai_inference_slot

DET_MODEL_DIR = "./models/paddleocr/ch_PP-OCRv4_det_infer"
REC_MODEL_DIR = "./models/paddleocr/ch_PP-OCRv4_rec_infer"
CLS_MODEL_DIR = "./models/paddleocr/ch_ppocr_mobile_v2.0_cls_infer"

_ocr_engine = None

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


def _decode_image(blob_bytes: bytes):
    try:
        import cv2
        arr = np.frombuffer(blob_bytes, np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is not None:
            return img
    except Exception:
        pass
    try:
        import io
        from PIL import Image
        img_pil = Image.open(io.BytesIO(blob_bytes)).convert("RGB")
        return np.array(img_pil)[:, :, ::-1]
    except Exception:
        pass
    return None


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

    try:
        ocr = get_ocr_engine()
        with ai_inference_slot("ocr"):
            result = ocr.ocr(img, cls=True)
    except Exception as e:
        print(f"[ERROR] OCR失败 {table_name}.{field_col_name} record={record_id}: {e}")
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
