import os


DB_CONFIGS = {
    "mysql": {
        "host": "127.0.0.1",
        "port": 3306,
        "user": "root",
        "password": os.environ.get("DB_PASSWORD", "rootpass123"),
        "databases": ["ecommerce_db", "fintech_db"],
    },
    "postgresql": {
        "host": "127.0.0.1",
        "port": 5432,
        "user": "postgres",
        "password": os.environ.get("DB_PASSWORD", "rootpass123"),
        "databases": ["healthcare_db", "govservice_db"],
    },
}

SENSITIVE_LEVEL_MAP = {
    "GPS_COORDINATE": "L2",
    "IP_ADDRESS": "L2",
    "MAC_ADDRESS": "L2",
    "CHINESE_NAME": "L3",
    "PHONE_NUMBER": "L3",
    "EMAIL": "L3",
    "ADDRESS": "L3",
    "LICENSE_PLATE": "L3",
    "SOCIAL_SECURITY_NO": "L3",
    "HOUSING_FUND_NO": "L3",
    "MEDICAL_INSURANCE_NO": "L3",
    "VIN_CODE": "L3",
    "MEDICAL_RECORD_NO": "L3",
    "USCC": "L3",
    "BUSINESS_LICENSE_NO": "L3",
    "ID_CARD": "L4",
    "BANK_CARD": "L4",
    "PASSPORT": "L4",
    "MILITARY_ID": "L4",
    "PASSWORD_OR_SECRET": "L4",
}

OUTPUT_CSV = "output/upload.csv"

# ── 时间预算 ─────────────────────────────────────────────────────
# 总时限:30 分钟(赛题硬性要求)
MAX_SCAN_MINUTES = 30

# 单表时间预算
TABLE_TIMEOUT_SECONDS = 300

# ── 抽样扫描(大表保护) ────────────────────────────────────────
# 超过该估算行数的表启用分层抽样
SAMPLE_THRESHOLD = 50_000
# 单表抽样目标行数(头/中/尾 三段各 1/3)
SAMPLE_ROWS_PER_TABLE = 6_000

# ── 单值长度保护 ─────────────────────────────────────────────────
# extract_sensitive_from_value 单次最大输入长度
MAX_SCAN_LEN = 50_000
# JSON/XML 叶子节点超过该长度时截断再扫描
LEAF_TEXT_MAX_LEN = 5_000

# ── 并发配置 ─────────────────────────────────────────────────────
# DB 线程池大小。
# [官方推荐机型: i5-10400 / 16GB / CPU only / Windows 11]
# 多线程 + PaddleOCR 在 Windows 上易段错误,DB_WORKERS=1 走主线程串行扫描是最稳的。
# 非 OCR 表毫秒级、OCR 单图 ~1-2s,串行也能在 30min 内扫完 4 个库。
DB_WORKERS = 1
# CSV 写入缓冲区
WRITER_BUFFER_SIZE = 100

# ── BLOB 表行数保护 ──────────────────────────────────────────────
# 含 BLOB/BYTEA 列的表最多扫这么多行。
#
# 原值 80 太保守:example.csv 里 kyc_verification.doc_image 有 18 行命中、
# medical_images.img_data 19 行,这些表实际总行数常在几百,限到 80 行会漏掉大量答案。
#
# 调整为 400 的计算依据(官方 16GB 机):
#   - OCR 单图稳态推理约 1-2s
#   - 400 行 × 2s = 800s,超出单表 300s 预算
#   - 单表预算会提前截断,实际能扫到约 150 张
#   - 留约 150s 给 OCR 重建/失败恢复 + 敏感正则扫描
#   - 这样在不触发超时的前提下,尽可能多扫行,Recall 最大化
BLOB_TABLE_MAX_ROWS = 400
