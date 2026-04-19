import pymysql
import sys

sys.stdout.reconfigure(encoding='utf-8')

# Analyze the mojibake
# Looking at the hex: c3a5c2aec2a2 = Ã¥Â®Â¨ in UTF-8 encoding of latin1 bytes

# The original string contains bytes like 0xc3 0xa5 which when interpreted as UTF-8
# becomes these "mojibake" characters

# Let's try different approaches
def try_fix_mojibake(s):
    """Try to fix mojibake by various methods"""
    results = []
    
    # Method 1: Try Latin-1 decoding first (for mojibake where UTF-8 bytes were interpreted as latin-1)
    try:
        # The string contains characters that came from UTF-8 bytes being decoded as latin-1
        # So we need to encode back to latin-1 and decode as UTF-8
        latin1_bytes = s.encode('latin-1')
        utf8_fixed = latin1_bytes.decode('utf-8')
        results.append(('latin1->utf8', utf8_fixed))
    except Exception as e:
        results.append(('latin1->utf8', f'FAILED: {e}'))
    
    return results

# Connect and get data
conn = pymysql.connect(
    host='127.0.0.1', port=3306, user='root', password='rootpass123',
    database='ecommerce_db', charset='utf8mb4'
)

cur = conn.cursor()
cur.execute("SELECT content FROM customer_feedback LIMIT 2")
print("=== Testing different fix approaches ===\n")

for i, row in enumerate(cur.fetchall()):
    raw = row[0]
    print(f"--- Record {i+1} ---")
    print(f"Raw: {repr(raw)[:120]}")
    
    for method, result in try_fix_mojibake(raw):
        print(f"{method}: {repr(result)[:120]}")
    print()

conn.close()
