import csv
import sys

sys.stdout.reconfigure(encoding='utf-8')

# Read CSV and check encoding
with open('output/upload.csv', 'rb') as f:
    raw_bytes = f.read(500)

print(f"First 100 bytes (hex): {raw_bytes[:100].hex()}")
print()

# Try decoding as different encodings
for enc in ['utf-8', 'utf-8-sig', 'gbk', 'gb2312', 'latin1']:
    try:
        s = raw_bytes.decode(enc, errors='replace')
        print(f"{enc}: {s[:80]}")
    except Exception as e:
        print(f"{enc}: FAILED - {e}")

print()

# Check if BOM present
if raw_bytes[:3] == b'\xef\xbb\xbf':
    print("UTF-8 BOM detected!")
elif raw_bytes[:4] == b'\xff\xfe':
    print("UTF-16 LE BOM detected!")
elif raw_bytes[:4] == b'\xfe\xff':
    print("UTF-16 BE BOM detected!")
else:
    print("No BOM detected")

# Check a Chinese character byte sequence
# "客户" in UTF-8: E5 AE A2 E6 88 B7
print()
print("Looking for UTF-8 encoded Chinese in first 200 bytes...")
for enc in ['utf-8']:
    s = raw_bytes[:200].decode(enc, errors='replace')
    if any('\u4e00' <= c <= '\u9fa5' for c in s):
        print(f"UTF-8 has valid Chinese: {s[:80]}")
    else:
        print("UTF-8 has no valid Chinese characters")
