"""
BLOB/图片/文档扫描器 v5.1 (架构师优化版)。

优化重点(联动 patterns.py & encoded.py):
  1. OCR 多行文本拼接: 解决证件照姓名/地址被切行。
  2. 身份证号 X/N 容错: 解决 OCR 对末位 X 的空格截断及形近字误识。
  3. 姓名纠错映射: 针对小字体 OCR 常犯的字形错误进行逆向修复。
  4. 多路径并行扫描: 原文/数字修复/汉字修复/全修复，四路合并去重，极限拉升 Recall。
  5. 兼容 encoded.py 的入口调用逻辑。
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
            import fitz
            _PYMUPDF = fitz
            print("[INFO] PyMuPDF 可用, PDF 将直接抽文本")
        except Exception as e:
            print(f"[INFO] PyMuPDF 不可用, PDF 路径将退化或返空: {e}")
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


# ═══════════════════════════════════════════════════════════════
# 数字类 OCR 纠错 (字母→数字)
# ═══════════════════════════════════════════════════════════════
OCR_CORRECTION_MAP = {
    'O': '0', 'o': '0', 'Q': '0', 'D': '0',
    'I': '1', 'l': '1', 'i': '1', '|': '1',
    'Z': '2', 'z': '2',
    'S': '5', 's': '5',
    'G': '6', 'b': '6',
    'T': '7',
    'B': '8',
    'g': '9', 'q': '9',
}
# 匹配至少6个字符的数字疑似串
_DIGIT_LIKE = re.compile(r"[0-9OoQDIlLiZzSsGbTBgq|]{6,}")

def correct_ocr_text(text: str) -> str:
    """
    数字区段 OCR 纠错,特殊处理:
      - 18位 + 末位 X/x → 末位保留为 'X',前 17 位纠错
      - 18位 + 末位 N/n → 猜测为身份证 X 末位误识,改成 'X'
      - 其他长度段全部按 map 纠错
    """
    def _correct_segment(m):
        seg = m.group()
        # 18位长度: 处理身份证 X/N 末位误识
        if len(seg) == 18:
            last = seg[-1]
            if last in "XxNn":
                front = "".join(OCR_CORRECTION_MAP.get(c, c) for c in seg[:17])
                return front + 'X'
        # 通用数字纠错
        return "".join(OCR_CORRECTION_MAP.get(c, c) for c in seg)
    
    return _DIGIT_LIKE.sub(_correct_segment, text)


# ═══════════════════════════════════════════════════════════════
# 姓名汉字 OCR 纠错 (OCR 字形相近误识)
# ═══════════════════════════════════════════════════════════════
NAME_CHAR_FIX = {
    '郡': '邵',
    '偌': '储',
    '窃': '窦',
    '沟': '汲',
    '货': '贡',
    '历': '厉',
    '方': '万',  # '方'本身也是姓, 但在特定极高误报的业务字典中退化处理
    '姊': '姚',
    '妹': '姊',
    '漷': '漕',
    '潰': '漕',
    '湖': '郜',
    '郭': '郜',  # 郜 与 郭 在小字体下极像
}

def _name_char_retry_text(text: str) -> str:
    """
    姓名字形纠错: 仅对长度 2-4 的纯汉字 token 做首字映射。
    不改变原文, 返回纠错后的副本供二次扫描。
    """
    if not text:
        return text

    def _fix_token(m):
        tok = m.group()
        if len(tok) < 2 or len(tok) > 4:
            return tok
        first = tok[0]
        fixed = NAME_CHAR_FIX.get(first)
        if fixed and fixed != first:
            return fixed + tok[1:]
        return tok

    return re.sub(r"[\u4e00-\u9fa5]{2,4}", _fix_token, text)


# ═══════════════════════════════════════════════════════════════
# OCR 文本预处理 (清洗降噪)
# ═══════════════════════════════════════════════════════════════
_OCR_SPACE_IN_LONGNUM = re.compile(r"(\d)\s+(\d)")
_OCR_LABEL_COLON = re.compile(
    r"(姓名|名字|客户名|联系人|身份证号|身份证|手机|电话|联系电话|"
    r"银行卡号|卡号|病历号|就诊号|住址|地址|邮箱|邮件|持卡人|签发|"
    r"发卡行|开户行|户籍|籍贯|民族|出生|身份)\s*[:\uff1a]\s*",
)

_OCR_CERT_PREFIX_SPACE = re.compile(r"\b(MR|YB|mR|mr|Mr)\s*(\d)")
_OCR_MR_NORMALIZE = re.compile(r"\b[mM][rR](?=\d)")
_OCR_YB_NORMALIZE = re.compile(r"\b[yY][bB](?=\d)")
_OCR_CJK_SPACE = re.compile(r"([\u4e00-\u9fa5])[ \t]{1,2}([\u4e00-\u9fa5])")
_OCR_ID_X_SPACE = re.compile(r"(\d{17})\s+([XxNn])(?![\w\d])")

# 地址跨行吸附：保留省市区锚点
_ADDR_ADMIN_TAIL = re.compile(
    r"([\u4e00-\u9fa5]*(?:省|市|区|县|镇|乡|街道|路|街|弄|巷))\n"
    r"([\u4e00-\u9fa5\d][\u4e00-\u9fa5\d]*)"
)

def _preprocess_ocr_text(text: str) -> str:
    """
    OCR 文本预处理流水线：合并碎片、修复空格、统一病历前缀
    """
    if not text:
        return text

    # 1) Label 规整
    text = _OCR_LABEL_COLON.sub(lambda m: m.group(1) + ":", text)

    # 2) MR/YB 大小写归一
    text = _OCR_MR_NORMALIZE.sub("MR", text)
    text = _OCR_YB_NORMALIZE.sub("YB", text)

    # 3) 数字空格合并 (应对如 6222 0214 格式的银行卡)
    for _ in range(3):
        new = _OCR_SPACE_IN_LONGNUM.sub(r"\1\2", text)
        if new == text: break
        text = new

    # 4) 证件号前缀空格 (MR 123456 -> MR123456)
    text = _OCR_CERT_PREFIX_SPACE.sub(r"\1\2", text)

    # 5) 身份证末位空格截断修复
    text = _OCR_ID_X_SPACE.sub(r"\1\2", text)

    # 6) 汉字间单空格合并 (如 "张 三")
    for _ in range(2):
        new = _OCR_CJK_SPACE.sub(r"\1\2", text)
        if new == text: break
        text = new

    # 7) 地址跨行合并 (不丢失核心锚点)
    text_joined = text
    for _ in range(3):
        new = _ADDR_ADMIN_TAIL.sub(r"\1\2", text_joined)
        if new == text_joined: break
        text_joined = new

    # 8) 多行短汉字合并 (专门应对竖排版姓名被切成两行)
    lines = text_joined.split("\n")
    merged_lines = []
    i = 0
    while i < len(lines):
        cur = lines[i].strip()
        if (i + 1 < len(lines)
                and 0 < len(cur) <= 5
                and all('\u4e00' <= c <= '\u9fa5' for c in cur)):
            nxt = lines[i + 1].strip()
            if (0 < len(nxt) <= 5
                    and all('\u4e00' <= c <= '\u9fa5' for c in nxt)
                    and len(cur) + len(nxt) <= 6):
                merged_lines.append(cur + nxt)
                i += 2
                continue
        merged_lines.append(lines[i])
        i += 1
    
    return "\n".join(merged_lines)


# ═══════════════════════════════════════════════════════════════
# finding 构造与文件嗅探
# ═══════════════════════════════════════════════════════════════
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

def _normalize_to_bytes(blob):
    if blob is None: return None
    if isinstance(blob, memoryview): return bytes(blob)
    if isinstance(blob, bytearray): return bytes(blob)
    if isinstance(blob, bytes): return blob
    if isinstance(blob, str):
        s = blob.strip()
        if s.startswith(r'\x') and len(s) > 4 and (len(s) - 2) % 2 == 0:
            try: return bytes.fromhex(s[2:])
            except ValueError: return None
    return None

def _sniff_file_type(data: bytes) -> str:
    if not data or len(data) < 8: return "unknown"
    if data[:4] == b'%PDF': return "pdf"
    if data[:2] == b'\xff\xd8' or data[:4] == b'\x89PNG' or data[:4] == b'GIF8' or data[:2] == b'BM' or data[:4] == b'RIFF':
        return "image"
    if data[:4] == b'PK\x03\x04':
        head = data[:4096]
        if b'word/document.xml' in head or b'word/' in head or b'[Content_Types].xml' in head:
            return "docx"
        if b'xl/workbook.xml' in head or b'xl/' in head:
            return "xlsx"
    return "unknown"


# ═══════════════════════════════════════════════════════════════
# PDF / DOCX / XLSX 文本抽取
# ═══════════════════════════════════════════════════════════════
def _extract_pdf_text(data: bytes) -> str:
    fitz = _get_pymupdf()
    if fitz is None: return ""
    try: doc = fitz.open(stream=data, filetype="pdf")
    except Exception: return ""

    try:
        page_count = min(len(doc), PDF_MAX_PAGES)
        texts, total_len, digital_text_empty = [], 0, True

        for i in range(page_count):
            try: t = doc[i].get_text("text") or ""
            except Exception: t = ""
            if t.strip():
                digital_text_empty = False
                texts.append(t)
                total_len += len(t)
                if total_len > DOC_TEXT_MAX_LEN: break

        if not digital_text_empty:
            return "\n".join(texts)[:DOC_TEXT_MAX_LEN]
        
        if ocr_disabled(): return ""

        ocr_texts = []
        for i in range(page_count):
            try:
                pix = doc[i].get_pixmap(dpi=PDF_OCR_DPI)
                t = get_ocr_text(pix.tobytes("png"))
                if t:
                    ocr_texts.append(t)
                    if sum(len(x) for x in ocr_texts) > DOC_TEXT_MAX_LEN: break
            except Exception: pass
        return "\n".join(ocr_texts)[:DOC_TEXT_MAX_LEN]
    finally:
        try: doc.close()
        except Exception: pass

def _extract_docx_text(data: bytes) -> str:
    docx_lib = _get_docx()
    if docx_lib is None: return ""
    try:
        doc = docx_lib.Document(io.BytesIO(data))
        texts, total = [], 0
        for para in doc.paragraphs:
            if para.text:
                texts.append(para.text)
                total += len(para.text)
                if total > DOC_TEXT_MAX_LEN: break
        if total < DOC_TEXT_MAX_LEN:
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text:
                            texts.append(cell.text)
                            total += len(cell.text)
                            if total > DOC_TEXT_MAX_LEN: break
                    if total > DOC_TEXT_MAX_LEN: break
                if total > DOC_TEXT_MAX_LEN: break
        return "\n".join(texts)[:DOC_TEXT_MAX_LEN]
    except Exception: return ""

def _extract_xlsx_text(data: bytes) -> str:
    xl = _get_openpyxl()
    if xl is None: return ""
    try:
        wb = xl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        texts, total = [], 0
        for sheet in wb.worksheets:
            for row in sheet.iter_rows(values_only=True):
                for cell in row:
                    if cell is not None:
                        s = str(cell)
                        if s:
                            texts.append(s)
                            total += len(s)
                            if total > DOC_TEXT_MAX_LEN: break
                if total > DOC_TEXT_MAX_LEN: break
            if total > DOC_TEXT_MAX_LEN: break
        try: wb.close()
        except Exception: pass
        return "\n".join(texts)[:DOC_TEXT_MAX_LEN]
    except Exception: return ""


# ═══════════════════════════════════════════════════════════════
# 核心引擎：多路径扫描去重 (防止单点失效)
# ═══════════════════════════════════════════════════════════════
def _collect_findings_multipath(text, record_id, table_name, field_col_name,
                                 db_type, db_name):
    """
    核心战术：通过四条路径(原样、修数字、修汉字、双修)提取。
    任一路径命中且符合 patterns.py 规范的数据，都会被合并去重。
    极大缓解 OCR 极其恶劣情况下的漏报问题。
    """
    if not text:
        return []

    paths = [text]

    corrected_digit = correct_ocr_text(text)
    if corrected_digit != text:
        paths.append(corrected_digit)

    corrected_name = _name_char_retry_text(text)
    if corrected_name != text:
        paths.append(corrected_name)

    if corrected_digit != text:
        corrected_both = _name_char_retry_text(corrected_digit)
        if corrected_both not in (text, corrected_digit, corrected_name):
            paths.append(corrected_both)

    findings = []
    seen = set()
    for scan_text in paths:
        # 调用我们已调优的 patterns.py 底层引擎
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

def _collect_findings_simple(text, record_id, table_name, field_col_name,
                              db_type, db_name):
    """针对无需纠错的结构化文档提取文本。"""
    if not text: return []
    findings = []
    seen = set()
    for stype, val in extract_sensitive_from_value(text):
        key = (stype, val)
        if key not in seen:
            seen.add(key)
            findings.append(_make_finding(
                db_type, db_name, table_name, field_col_name,
                record_id, stype, val,
            ))
    return findings


# ═══════════════════════════════════════════════════════════════
# 对外统一入口
# ═══════════════════════════════════════════════════════════════
def scan_blob_data(blob_bytes, record_id, table_name, field_col_name,
                   db_type, db_name):
    """
    BLOB / 文档 / 图像 字段扫描统一入口。
    供 encoded.py 和底层核心引擎调用。
    """
    data = _normalize_to_bytes(blob_bytes)
    if not data:
        return []

    ftype = _sniff_file_type(data)

    if ftype == "pdf":
        raw_text = _extract_pdf_text(data)
        return _collect_findings_simple(raw_text, record_id, table_name, field_col_name, db_type, db_name)

    if ftype == "docx":
        raw_text = _extract_docx_text(data)
        return _collect_findings_simple(raw_text, record_id, table_name, field_col_name, db_type, db_name)

    if ftype == "xlsx":
        raw_text = _extract_xlsx_text(data)
        return _collect_findings_simple(raw_text, record_id, table_name, field_col_name, db_type, db_name)

    # 图像或未知格式 -> 触发高规格容错处理: OCR + 预处理 + 多路径扫描
    if ocr_disabled():
        return []
        
    raw_text = get_ocr_text(data)
    if not raw_text:
        return []
        
    processed = _preprocess_ocr_text(raw_text)
    
    return _collect_findings_multipath(
        processed, record_id, table_name, field_col_name,
        db_type, db_name,
    )

# 别名: 兼容旧版本代码中的调用习惯
scan_blob_field = scan_blob_data
