"""
研究报告 Markdown → PDF 转换脚本（v3）
修复：① 宽松内容区边距（68~774pt）彻底隔离页眉页脚
     ② 双阶段渲染（Story先写临时文件，再叠加页眉页脚写最终文件）
     ③ 优先使用 Windows 系统 CJK 字体渲染中文页眉
用法: python scripts/md_to_pdf.py
"""
import sys, os, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import fitz
import markdown as md_lib

BASE     = os.path.dirname(os.path.abspath(__file__))
MD_FILE  = os.path.join(BASE, "../docs/交付物/研究报告.md")
OUT_FILE = os.path.join(BASE, "../docs/交付物/研究报告.pdf")
TMP_FILE = OUT_FILE + ".stage1.pdf"

# ══════════════════════════════════════════════════════════════
# 1. Markdown → HTML
# ══════════════════════════════════════════════════════════════
with open(MD_FILE, encoding="utf-8") as f:
    md_text = f.read()

html_body = md_lib.markdown(
    md_text,
    extensions=["tables", "fenced_code", "nl2br"],
)

CSS = """
body {
    font-family: sans-serif;
    font-size: 10.5pt;
    line-height: 1.8;
    color: #111;
}
h1 {
    font-size: 16pt;
    font-weight: bold;
    text-align: center;
    margin: 18pt 0 8pt;
    border-bottom: 2px solid #222;
    padding-bottom: 5pt;
}
h2 {
    font-size: 13pt;
    font-weight: bold;
    margin: 14pt 0 5pt;
    color: #1a1a6e;
    border-left: 4px solid #1a1a6e;
    padding-left: 7pt;
}
h3 {
    font-size: 11.5pt;
    font-weight: bold;
    margin: 10pt 0 4pt;
    color: #1a4080;
}
h4 {
    font-size: 10.5pt;
    font-weight: bold;
    margin: 8pt 0 3pt;
    color: #333;
}
p {
    margin: 5pt 0;
    text-align: justify;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin: 7pt 0;
    font-size: 9pt;
}
th {
    background: #1a1a6e;
    color: white;
    padding: 4pt 6pt;
    text-align: left;
    font-weight: bold;
}
td {
    border: 0.5pt solid #bbb;
    padding: 3pt 6pt;
    vertical-align: top;
}
tr:nth-child(even) td {
    background: #f0f2ff;
}
code {
    font-family: monospace;
    font-size: 8.5pt;
    background: #f0f0f0;
    padding: 1pt 3pt;
}
pre {
    background: #f4f4f4;
    border: 0.5pt solid #ccc;
    padding: 6pt 8pt;
    margin: 5pt 0;
    font-family: monospace;
    font-size: 8pt;
    white-space: pre-wrap;
    word-break: break-all;
}
ul, ol {
    margin: 4pt 0;
    padding-left: 20pt;
}
li {
    margin: 2pt 0;
}
hr {
    border: none;
    border-top: 1pt solid #aaa;
    margin: 8pt 0;
}
blockquote {
    border-left: 3pt solid #888;
    padding-left: 9pt;
    color: #555;
    margin: 5pt 0;
}
"""

HTML = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'/>"
    f"<style>{CSS}</style></head><body>{html_body}</body></html>"
)

# ══════════════════════════════════════════════════════════════
# 2. 页面布局参数
#    A4 = 595 × 842 pt
#    页眉区: y =  0 ~ 62   (线 y=58, 文字基线 y=48)
#    内容区: y = 68 ~ 774  (与页眉线间距 10pt，与页脚线间距 8pt)
#    页脚区: y = 782 ~ 842 (线 y=782, 文字基线 y=800)
# ══════════════════════════════════════════════════════════════
PW, PH   = 595, 842
MEDIABOX = fitz.Rect(0, 0, PW, PH)
CONTENT  = fitz.Rect(58, 68, 537, 774)   # 左右各留 58/58 pt

# ══════════════════════════════════════════════════════════════
# 3. 阶段一：Story 渲染到临时文件
# ══════════════════════════════════════════════════════════════
print("[1/3] 渲染 Story 内容...")
story  = fitz.Story(html=HTML, em=10.5)
writer = fitz.DocumentWriter(TMP_FILE)
more   = True
while more:
    dev = writer.begin_page(MEDIABOX)
    more, _ = story.place(CONTENT)
    story.draw(dev)
    writer.end_page()
writer.close()
print(f"      临时文件写出: {TMP_FILE}")

# ══════════════════════════════════════════════════════════════
# 4. 检测可用 CJK 字体（Windows 系统字体，按优先级）
# ══════════════════════════════════════════════════════════════
CJK_CANDIDATES = [
    "C:/Windows/Fonts/msyh.ttc",       # 微软雅黑（首选）
    "C:/Windows/Fonts/msyhbd.ttc",     # 微软雅黑 Bold
    "C:/Windows/Fonts/simhei.ttf",     # 黑体
    "C:/Windows/Fonts/simsun.ttc",     # 宋体
    "C:/Windows/Fonts/simfang.ttf",    # 仿宋
]
CJK_FONT = next((p for p in CJK_CANDIDATES if os.path.exists(p)), None)
print(f"[2/3] CJK 字体: {CJK_FONT or '未找到，使用英文回退'}")

HDR_ZH = "数据库敏感字段自动识别与安全管控系统  研究报告"
HDR_EN = "Sensitive Field Recognition & Security Control System - Research Report"

# ══════════════════════════════════════════════════════════════
# 5. 阶段二：叠加页眉页脚 → 最终文件
# ══════════════════════════════════════════════════════════════
print("[3/3] 叠加页眉页脚...")
doc   = fitz.open(TMP_FILE)
total = doc.page_count

for i, page in enumerate(doc):
    # ── 页眉 ─────────────────────────────────────────────────
    # 横线（在内容区 y=68 之上，gap=10pt）
    page.draw_line(
        fitz.Point(50, 58), fitz.Point(545, 58),
        color=(0.1, 0.1, 0.45), width=0.6,
    )
    # 页眉文字（基线 y=48，字体高 8pt，不碰横线 y=58）
    if CJK_FONT:
        page.insert_text(
            fitz.Point(50, 48), HDR_ZH,
            fontfile=CJK_FONT, fontsize=8,
            color=(0.25, 0.25, 0.25),
        )
    else:
        page.insert_text(
            fitz.Point(50, 48), HDR_EN,
            fontname="helv", fontsize=7.5,
            color=(0.25, 0.25, 0.25),
        )

    # ── 页脚 ─────────────────────────────────────────────────
    # 横线（内容区 y=774 之下，gap=8pt）
    page.draw_line(
        fitz.Point(50, 782), fitz.Point(545, 782),
        color=(0.1, 0.1, 0.45), width=0.6,
    )
    # 页码（基线 y=800，居中）
    pg_text = f"- {i + 1} / {total} -"
    text_w  = fitz.get_text_length(pg_text, fontname="helv", fontsize=9)
    page.insert_text(
        fitz.Point((PW - text_w) / 2, 800),
        pg_text,
        fontname="helv", fontsize=9,
        color=(0.25, 0.25, 0.25),
    )

# 保存到 OUT_FILE（与 TMP_FILE 不同路径，避免 incremental 错误）
doc.save(OUT_FILE, garbage=4, deflate=True)
doc.close()

# 清理临时文件（Windows 可能延迟释放句柄，忽略删除失败）
try:
    import gc; gc.collect()
    os.remove(TMP_FILE)
except OSError:
    pass

print(f"\n[OK] PDF generated: {os.path.abspath(OUT_FILE)}")
print(f"     Total pages  : {total}")
