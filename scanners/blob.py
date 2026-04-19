"""
BLOB/图片/文档扫描器。

v3 特性:
  - 文件魔数嗅探: PDF / DOCX / XLSX / IMAGE / UNKNOWN 五路分发
  - PDF 优先抽数字文本,扫描版 fallback 到 OCR 子进程
  - DOCX / XLSX 懒加载(库未装时静默返空)
  - OCR 路径预处理:长数字串空格合并、label 冒号规整
  - OCR 数字类纠错(O→0 / I→1 等),只作用于图片路径

对外 API 不变:
  scan_blob_field(blob_bytes, record_id, table_name,
                  field_col_name, db_type, db_name) -> list[finding]
"""
import re
import io

from core.patterns import extract_sensitive_from_value
from core.config import SENSITIVE_LEVEL_MAP
from scanners.ocr_client import get_ocr_text, ocr_disabled


# ── 文档解析参数 ─────────────────────────────────────────────────
PDF_MAX_PAGES = 20
PDF_OCR_DPI = 150
DOC_TEXT_MAX_LEN = 500_000


# ── 延迟加载容器 ─────────────────────────────────────────────────
_PYMUPDF_TRIED = False
_PYMUPDF = None
_DOCX_TRIED = False
_DOCX = None
_OPENPYXL_TRIED = False
_OPENPYXL = None


def _get_pymupdf():
    global _PYMUPDF_TRIED, _PYMUPDF
    if not _PYMUPDF_TRIED:
        _PYMUPDF_TRIED = True
        try:
            import fitz  # PyMuPDF
            _PYMUPDF = fitz
            print("[INFO] PyMuPDF 可用,PDF 将直接抽文本")
        except Exception as e:
            print(f"[INFO] PyMuPDF 不可用,PDF 路径将返空: {e}")
    return _PYMUPDF


def _get_docx():
    global _DOCX_TRIED, _DOCX
    if not _DOCX_TRIED:
        _DOCX_TRIED = True
        try:
            import docx
            _DOCX = docx
            print("[INFO] python-docx 可用")
        except Exception:
            pass
    return _DOCX


def _get_openpyxl():
    global _OPENPYXL_TRIED, _OPENPYXL
    if not _OPENPYXL_TRIED:
        _OPENPYXL_TRIED = True
        try:
            import openpyxl
            _OPENPYXL = openpyxl
            print("[INFO] openpyxl 可用")
        except Exception:
            pass
    return _OPENPYXL


# ── OCR 数字类纠错(图片路径专用) ────────────────────────────────
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


def correct_ocr_text(text: str) -> str:
    def _correct_segment(m):
        seg = m.group()
        return "".join(OCR_CORRECTION_MAP.get(c, c) for c in seg)
    return _DIGIT_LIKE.sub(_correct_segment, text)


# ── OCR 文本预处理(合并空格切碎的长数字串 + label 规整) ──────────
_OCR_SPACE_IN_LONGNUM = re.compile(r"(\d)\s+(\d)")
_OCR_LABEL_COLON = re.compile(
    r"(姓名|名字|客户名|联系人|身份证号|身份证|手机|电话|联系电话|"
    r"银行卡号|卡号|病历号|就诊号|住址|地址|邮箱|邮件)\s*[:\uff1a]\s*",
)


def _preprocess_ocr_text(text: str) -> str:
    """
    OCR 文本预处理(仅作用于图片路径):
      - label 冒号规整(全角半角冒号统一成无空格半角)
      - 合并被空格切碎的长数字串:
          "440106 19900101 1234" → "440106199001011234"
        2 轮足够把 "6-6-6" 格式合成 18 位
    """
    if not text:
        return text
    text = _OCR_LABEL_COLON.sub(lambda m: m.group(1) + ":", text)
    for _ in range(2):
        new = _OCR_SPACE_IN_LONGNUM.sub(r"\1\2", text)
        if new == text:
            break
        text = new
    return text


# ── finding 构造 ─────────────────────────────────────────────────
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


# ── 字节规范化 ───────────────────────────────────────────────────
def _normalize_to_bytes(blob):
    if blob is None:
        return None
    if isinstance(blob, memoryview):
        return bytes(blob)
    if isinstance(blob, bytearray):
        return bytes(blob)
    if isinstance(blob, bytes):
        return blob
    if isinstance(blob, str):
        s = blob.strip()
        if s.startswith(r'\x') and len(s) > 4 and (len(s) - 2) % 2 == 0:
            try:
                return bytes.fromhex(s[2:])
            except ValueError:
                return None
        return None
    return None


# ── 文件类型嗅探 ─────────────────────────────────────────────────
def _sniff_file_type(data: bytes) -> str:
    if not data or len(data) < 8:
        return "unknown"

    if data[:4] == b'%PDF':
        return "pdf"

    if (data[:2] == b'\xff\xd8'
            or data[:4] == b'\x89PNG'
            or data[:4] == b'GIF8'
            or data[:2] == b'BM'
            or data[:4] == b'RIFF'):
        return "image"

    if data[:4] == b'PK\x03\x04':
        head = data[:4096]
        if b'word/document.xml' in head or b'word/' in head:
            return "docx"
        if b'xl/workbook.xml' in head or b'xl/' in head:
            return "xlsx"
        if b'[Content_Types].xml' in head:
            return "docx"
        return "unknown"

    return "unknown"


# ── PDF 文本抽取 ─────────────────────────────────────────────────
def _extract_pdf_text(data: bytes) -> str:
    fitz = _get_pymupdf()
    if fitz is None:
        return ""

    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception as e:
        print(f"[WARN] PDF 打开失败: {e}")
        return ""

    try:
        page_count = min(len(doc), PDF_MAX_PAGES)
        texts = []
        total_len = 0
        digital_text_empty = True

        # 第一轮: 直接抽文本(数字版 PDF)
        for i in range(page_count):
            try:
                t = doc[i].get_text("text") or ""
            except Exception:
                t = ""
            if t.strip():
                digital_text_empty = False
                texts.append(t)
                total_len += len(t)
                if total_len > DOC_TEXT_MAX_LEN:
                    break

        if not digital_text_empty:
            return "\n".join(texts)[:DOC_TEXT_MAX_LEN]

        # 第二轮: 扫描版 PDF,每页转图交给 OCR 子进程
        if ocr_disabled():
            return ""

        ocr_texts = []
        for i in range(page_count):
            try:
                pix = doc[i].get_pixmap(dpi=PDF_OCR_DPI)
                png_bytes = pix.tobytes("png")
                t = get_ocr_text(png_bytes)
                if t:
                    ocr_texts.append(t)
                    if sum(len(x) for x in ocr_texts) > DOC_TEXT_MAX_LEN:
                        break
            except Exception as e:
                print(f"[WARN] PDF 第 {i} 页 OCR 失败: {e}")
        return "\n".join(ocr_texts)[:DOC_TEXT_MAX_LEN]

    finally:
        try:
            doc.close()
        except Exception:
            pass


def _extract_docx_text(data: bytes) -> str:
    docx_lib = _get_docx()
    if docx_lib is None:
        return ""
    try:
        doc = docx_lib.Document(io.BytesIO(data))
        texts = []
        total = 0
        for para in doc.paragraphs:
            if para.text:
                texts.append(para.text)
                total += len(para.text)
                if total > DOC_TEXT_MAX_LEN:
                    break
        if total < DOC_TEXT_MAX_LEN:
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text:
                            texts.append(cell.text)
                            total += len(cell.text)
                            if total > DOC_TEXT_MAX_LEN:
                                break
                    if total > DOC_TEXT_MAX_LEN:
                        break
                if total > DOC_TEXT_MAX_LEN:
                    break
        return "\n".join(texts)[:DOC_TEXT_MAX_LEN]
    except Exception as e:
        print(f"[WARN] DOCX 解析失败: {e}")
        return ""


def _extract_xlsx_text(data: bytes) -> str:
    xl = _get_openpyxl()
    if xl is None:
        return ""
    try:
        wb = xl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        texts = []
        total = 0
        for sheet in wb.worksheets:
            for row in sheet.iter_rows(values_only=True):
                for cell in row:
                    if cell is None:
                        continue
                    s = str(cell)
                    if s:
                        texts.append(s)
                        total += len(s)
                        if total > DOC_TEXT_MAX_LEN:
                            break
                if total > DOC_TEXT_MAX_LEN:
                    break
            if total > DOC_TEXT_MAX_LEN:
                break
        try:
            wb.close()
        except Exception:
            pass
        return "\n".join(texts)[:DOC_TEXT_MAX_LEN]
    except Exception as e:
        print(f"[WARN] XLSX 解析失败: {e}")
        return ""


# ── 扫描结果组装 ─────────────────────────────────────────────────
def _collect_findings(text, record_id, table_name, field_col_name,
                      db_type, db_name, apply_ocr_correction=False):
    """
    从文本抽敏感值。apply_ocr_correction=True 时额外扫一遍 OCR 数字纠错后的文本,
    双路径合并去重。PDF/DOCX/XLSX 抽出来的文字是精确的,不用纠错。
    """
    if not text:
        return []

    findings = []
    seen = set()

    texts_to_scan = [text]
    if apply_ocr_correction:
        corrected = correct_ocr_text(text)
        if corrected != text:
            texts_to_scan.append(corrected)

    for scan_text in texts_to_scan:
        for stype, val in extract_sensitive_from_value(scan_text):
            key = (stype, val)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_make_finding(
                db_type, db_name, table_name, field_col_name,
                record_id, stype, val,
            ))
    return findings


# ── 对外入口 ─────────────────────────────────────────────────────
def scan_blob_field(blob_bytes, record_id, table_name, field_col_name,
                    db_type, db_name):
    """
    BLOB / 文档 字段扫描入口。

    流程:
      1. 规范化成 bytes
      2. 文件魔数嗅探,路由到 PDF / DOCX / XLSX / IMAGE / UNKNOWN
      3. PDF:先抽数字文本,失败再转图 OCR
         DOCX/XLSX:直接抽文本(需对应库可用,否则返空)
         IMAGE/UNKNOWN:走 OCR 子进程 + 预处理 + 数字纠错
    """
    data = _normalize_to_bytes(blob_bytes)
    if not data:
        return []

    ftype = _sniff_file_type(data)

    if ftype == "pdf":
        raw_text = _extract_pdf_text(data)
        return _collect_findings(
            raw_text, record_id, table_name, field_col_name,
            db_type, db_name, apply_ocr_correction=False,
        )

    if ftype == "docx":
        raw_text = _extract_docx_text(data)
        return _collect_findings(
            raw_text, record_id, table_name, field_col_name,
            db_type, db_name, apply_ocr_correction=False,
        )

    if ftype == "xlsx":
        raw_text = _extract_xlsx_text(data)
        return _collect_findings(
            raw_text, record_id, table_name, field_col_name,
            db_type, db_name, apply_ocr_correction=False,
        )

    # 图片 / 未知 → OCR 子进程 + 预处理 + 数字纠错
    if ocr_disabled():
        return []
    raw_text = get_ocr_text(data)
    if not raw_text:
        return []
    raw_text = _preprocess_ocr_text(raw_text)
    return _collect_findings(
        raw_text, record_id, table_name, field_col_name,
        db_type, db_name, apply_ocr_correction=True,
    )
