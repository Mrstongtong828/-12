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
# DB 线程池大小。
# [比赛机 i5-10400 / 16GB / CPU only / Windows 11]
# 多线程 + PaddleOCR 2.7 会触发段错误（paddle 内部线程在 GIL 切换时访问已释
# 放状态），即便 task_queue.py 的 Semaphore 已把 OCR 序列化。
# DB_WORKERS=1 时 main.py 会走主线程串行扫描跳过 ThreadPoolExecutor——这是
# 在"单图 OCR 约 1-2s、非 OCR 表毫秒级"前提下最稳的方案。
DB_WORKERS = 1
# CSV 写入缓冲区：每个 DB 线程攒够 N 条才统一 flush，降低锁竞争
WRITER_BUFFER_SIZE = 100
# ── BLOB 表行数保护 ──────────────────────────────────────────────
# 含 BLOB/BYTEA 列的表,无论估算行数多少,最多只扫这么多行。
# 理由:每张图 OCR 哪怕全走本地子进程,也比纯正则贵 2-3 个数量级;
#      一个几千行的 user_attachments 会把 TABLE_TIMEOUT_SECONDS 烧光,
#      而抽样扫 80 行对 F1 的覆盖已经够用(example.csv 里 binary_blob
#      抽样本来就很稀疏)。
BLOB_TABLE_MAX_ROWS = 80
