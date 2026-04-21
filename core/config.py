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
# v7(2026-04-21 第四轮)联动:
#   #1 BLOB 表 SQL 层跳过 NULL/tiny blob —— 继续保留
#   #2 OCR_POOL_SIZE 3→2,每 slot fraction 0.15→0.20(稳态优先)
#   #3 DB_WORKERS=2 保持(第二轮 4 已实证会摊稀)
#   #4 图片峰值削平:MAX_OCR_SIDE 960→800,PRE_SCALE 2000/1400→1600/1100
# 预算说明:
#   - 2 库并发、2 slot 吞吐;每 DB 实际占 1 slot,~1 call/s
#   - 450s × 1 ≈ 450 行负载(NULL 过滤后命中率高)
#   - fintech 第 2 张 BLOB 表(contract_archive)在同一 DB 线程里串行,
#     也有 450s 独占预算
#   - 总 wall-clock ≈ 900s BLOB(fintech 串行 2 张) + 120s 非 BLOB = ~17min
TABLE_TIMEOUT_SECONDS = 450

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
# 演进:
#   第二轮 DB_WORKERS=4 + 3 slot → 吞吐摊稀,FN 34→52 反弹
#   第三轮 DB_WORKERS=2 + 3 slot × 0.15 → OCR 仍频繁爆池,slot 永久停用后 FN→62
#   第四轮(本版本)DB_WORKERS=2 + 2 slot × 0.20 → 稳态优先,slot 数与 DB 数对齐
#
# 关键点:DB_WORKERS=2 和 OCR_POOL_SIZE=2 匹配 ——
#   每个 DB 扫描线程对应一个 OCR slot,不会有 slot 闲置,也不会有饥饿等待。
#   fintech 两张 BLOB 表(kyc + contract)在同一 DB 线程里串行,
#   每张都能吃满 450s × 1 slot 的吞吐(~400+ 行)。
#
#   - 非 BLOB 表 wall-clock ~120s(2 库并行)
#   - BLOB 表 wall-clock 由 fintech(含 2 张 BLOB 表串行)决定,约 900s
#   - 主线程只做 SQL/正则/dispatch,OCR 在 ocr_worker 子进程跑,无多线程段错误风险
DB_WORKERS = 2
# CSV 写入缓冲区
WRITER_BUFFER_SIZE = 100

# ── BLOB 表行数保护 ──────────────────────────────────────────────
# 含 BLOB/BYTEA 列的表最多扫这么多行。
#
# v7(2026-04-21 第四轮):保持 800。
# 配合 2-slot × 0.20 的稳态吞吐 + SQL NULL 过滤,单表 ~450 行有效 OCR 已绰绰有余。
# 提高到 800 是为了让 stream 迭代器能吐出足够多 NON-NULL 行(SQL 过滤后依然有
# 一定空 OCR 结果的图,所以提 20% 做缓冲)。
BLOB_TABLE_MAX_ROWS = 800
