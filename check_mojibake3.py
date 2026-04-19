import pymysql
import sys

sys.stdout.reconfigure(encoding='utf-8')

# Connect and get raw bytes
conn = pymysql.connect(
    host='127.0.0.1', port=3306, user='root', password='rootpass123',
    database='ecommerce_db', charset='utf8mb4'
)

cur = conn.cursor()
cur.execute("SELECT content FROM customer_feedback LIMIT 1")
row = cur.fetchone()
raw = row[0]

print(f"Type: {type(raw)}")
print(f"Length: {len(raw)}")
print()

# Try to understand the byte structure
# The mojibake characters suggest UTF-8 bytes were interpreted as latin-1/CP1252

# Let's try: encode with errors='surrogateescape', then decode
def try_fix_via_surrogateescape(s):
    try:
        # Encode to bytes using surrogateescape (preserves unmappable chars)
        b = s.encode('utf-8', errors='surrogateescape')
        # Try to decode as GBK (common Chinese encoding)
        result = b.decode('gbk', errors='ignore')
        return result
    except Exception as e:
        return f'FAILED: {e}'

# Try Latin-1 -> UTF-8
def try_latin1_utf8(s):
    try:
        # Convert each character to its ordinal, filter to 0-255 range
        latin1_bytes = bytes([ord(c) for c in s if ord(c) < 256])
        result = latin1_bytes.decode('utf-8', errors='ignore')
        return result
    except Exception as e:
        return f'FAILED: {e}'

print("=== Original ===")
print(f"repr: {repr(raw)[:200]}")
print()

# Print char by char for first 30 chars
print("=== Character analysis (first 30) ===")
for i, c in enumerate(raw[:30]):
    print(f"  {i}: U+{ord(c):04X} = '{c}'")

print()
print("=== Try Latin-1 filter ===")
result1 = try_latin1_utf8(raw)
print(f"Result: {result1[:200]}")

conn.close()
