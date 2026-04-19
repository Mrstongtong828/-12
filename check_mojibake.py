import pymysql
import csv
import sys

sys.stdout.reconfigure(encoding='utf-8')

# Test _fix_mojibake function
def _mojibake_to_bytes(s):
    _CP1252_EXTRA = {
        '\u20ac': 0x80, '\u201a': 0x82, '\u0192': 0x83, '\u201e': 0x84,
        '\u2026': 0x85, '\u2020': 0x86, '\u2021': 0x87, '\u02c6': 0x88,
        '\u2030': 0x89, '\u0160': 0x8a, '\u2039': 0x8b, '\u0152': 0x8c,
        '\u017d': 0x8e, '\u2018': 0x91, '\u2019': 0x92, '\u201c': 0x93,
        '\u201d': 0x94, '\u2022': 0x95, '\u2013': 0x96, '\u2014': 0x97,
        '\u02dc': 0x98, '\u2122': 0x99, '\u0161': 0x9a, '\u203a': 0x9b,
        '\u0153': 0x9c, '\u017e': 0x9e, '\u0178': 0x9f,
    }
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if cp < 0x100:
            out.append(cp)
        elif ch in _CP1252_EXTRA:
            out.append(_CP1252_EXTRA[ch])
        else:
            return None
    return bytes(out)

def _fix_mysql_mojibake(s):
    if not isinstance(s, str) or not s:
        return s
    if all(ord(ch) < 0x80 for ch in s):
        return s
    raw = _mojibake_to_bytes(s)
    if raw is None:
        return s
    try:
        fixed = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return s
    if fixed != s and any('\u4e00' <= ch <= '\u9fa5' for ch in fixed):
        return fixed
    return s

# Connect and get data
conn = pymysql.connect(
    host='127.0.0.1', port=3306, user='root', password='rootpass123',
    database='ecommerce_db', charset='utf8mb4'
)

cur = conn.cursor()
cur.execute("SELECT content FROM customer_feedback LIMIT 2")
print("=== Testing mojibake fix ===\n")

for row in cur.fetchall():
    raw = row[0]
    print(f"Raw (repr): {repr(raw)[:100]}")
    print(f"Raw bytes: {raw[:50].encode('latin1').hex()}")
    
    fixed = _fix_mysql_mojibake(raw)
    print(f"Fixed (repr): {repr(fixed)[:100]}")
    print()

conn.close()
