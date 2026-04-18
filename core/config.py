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
# 总时限：30 分钟
MAX_SCAN_MINUTES = 30

# 单表时间预算（原来 45s 太激进，会把大表截断到只扫到头部）
# 放宽到 300s，配合大表抽样策略
TABLE_TIMEOUT_SECONDS = 300

# ── 抽样扫描（性能 #11：大表保护）─────────────────────────────────
# 超过该估算行数的表启用分层抽样
SAMPLE_THRESHOLD = 50_000
# 单表抽样目标行数（头/中/尾 三段各 1/3）
SAMPLE_ROWS_PER_TABLE = 6_000

# ── 单值长度保护（性能 #12）─────────────────────────────────────
# extract_sensitive_from_value 单次最大输入长度
MAX_SCAN_LEN = 50_000
# JSON/XML 叶子节点超过该长度时截断再扫描
LEAF_TEXT_MAX_LEN = 5_000

# ── 并发配置（性能 #13/#14）─────────────────────────────────────
# DB 线程池大小：显著大于任务数，让 I/O 线程在 OCR 串行排队时继续扫描其他非 OCR 表
DB_WORKERS = 8
# CSV 写入缓冲区：每个 DB 线程攒够 N 条才统一 flush，降低锁竞争
WRITER_BUFFER_SIZE = 100
