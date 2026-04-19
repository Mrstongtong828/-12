import csv

with open('output/upload.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    rows = list(reader)

print(f'Total rows: {len(rows)}')

# ADDRESS 检查
addr_rows = [r for r in rows if r['sensitive_type'] == 'ADDRESS']
print(f'ADDRESS entries: {len(addr_rows)}')
print('=== ADDRESS samples ===')
for r in addr_rows[:5]:
    print(f'  {repr(r["extracted_value"])}')

# CHINESE_NAME 检查
name_rows = [r for r in rows if r['sensitive_type'] == 'CHINESE_NAME']
print(f'\nCHINESE_NAME entries: {len(name_rows)}')
print('=== CHINESE_NAME samples ===')
for r in name_rows[:10]:
    print(f'  {repr(r["extracted_value"])}')

# 检查坏模式
bad_patterns = ['审计员', '警官', '专员', '公积金提']
found_bad = [r for r in name_rows if any(bp in r['extracted_value'] for bp in bad_patterns)]
print(f'\n=== Bad patterns check ===')
if found_bad:
    print(f'FOUND {len(found_bad)} bad patterns:')
    for r in found_bad[:10]:
        print(f'  {repr(r["extracted_value"])}')
else:
    print('GOOD - No bad patterns found!')

# 按数据库统计
print('\n=== By database ===')
from collections import Counter
db_counts = Counter(r['db_name'] for r in rows)
for db, count in db_counts.items():
    print(f'  {db}: {count}')
