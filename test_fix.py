import pymysql
import sys

sys.stdout.reconfigure(encoding='utf-8')

# Test the fixed function
from core.db_connector import _fix_mysql_mojibake

# Connect and get data
conn = pymysql.connect(
    host='127.0.0.1', port=3306, user='root', password='rootpass123',
    database='ecommerce_db', charset='utf8mb4'
)

cur = conn.cursor()
cur.execute("SELECT content FROM customer_feedback LIMIT 3")
print("=== Testing fixed mojibake fix ===\n")

for i, row in enumerate(cur.fetchall()):
    raw = row[0]
    fixed = _fix_mysql_mojibake(raw)
    print(f"--- Record {i+1} ---")
    print(f"Raw:   {repr(raw)[:100]}")
    print(f"Fixed: {repr(fixed)[:100]}")
    print()

conn.close()
