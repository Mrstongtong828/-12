DB_CONFIGS = {
    "mysql": {
        "host": "127.0.0.1",
        "port": 3306,
        "user": "root",
        "password": "rootpass123",
        "databases": ["ecommerce_db", "fintech_db"],
    },
    "postgresql": {
        "host": "127.0.0.1",
        "port": 5432,
        "user": "postgres",
        "password": "rootpass123",
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
MAX_SCAN_MINUTES = 30
TABLE_TIMEOUT_SECONDS = 45
