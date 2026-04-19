import pymysql
import sys

# Set stdout to UTF-8
sys.stdout.reconfigure(encoding='utf-8')

conn = pymysql.connect(
    host='127.0.0.1', port=3306, user='root', password='rootpass123',
    database='ecommerce_db', charset='utf8mb4'
)

cur = conn.cursor()
cur.execute("SELECT content FROM customer_feedback LIMIT 3")
print("=== Raw DB content ===")
for row in cur.fetchall():
    print(repr(row[0]))
    print(f"  Bytes: {row[0].encode('utf-8', errors='replace')[:100].hex()}")
    print()

conn.close()
