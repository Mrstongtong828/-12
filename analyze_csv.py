import csv

# Read both CSVs
with open('output/upload_backup.csv', 'r', encoding='utf-8') as f:
    old_rows = list(csv.DictReader(f))

with open('output/upload.csv', 'r', encoding='utf-8') as f:
    new_rows = list(csv.DictReader(f))

print('=== Summary ===')
print(f'Old CSV: {len(old_rows)} rows')
print(f'New CSV: {len(new_rows)} rows')
print(f'Difference: {len(new_rows) - len(old_rows)} rows')

# Bad patterns to check
bad_patterns = ['审计员', '警官', '专员', '公积金提', '王审计', '张警官', '李专员', '公积金提']

# Check old CSV for bad patterns
old_name_rows = [r for r in old_rows if r['sensitive_type'] == 'CHINESE_NAME']
old_bad = [r for r in old_name_rows if any(bp in r['extracted_value'] for bp in bad_patterns)]

print(f'\n=== Bad pattern check (OLD CSV) ===')
print(f'CHINESE_NAME total: {len(old_name_rows)}')
print(f'With bad patterns: {len(old_bad)}')
if old_bad:
    for r in old_bad[:10]:
        print(f'  BAD: {repr(r["extracted_value"])}')

# Check new CSV for bad patterns
new_name_rows = [r for r in new_rows if r['sensitive_type'] == 'CHINESE_NAME']
new_bad = [r for r in new_name_rows if any(bp in r['extracted_value'] for bp in bad_patterns)]

print(f'\n=== Bad pattern check (NEW CSV) ===')
print(f'CHINESE_NAME total: {len(new_name_rows)}')
print(f'With bad patterns: {len(new_bad)}')
if new_bad:
    for r in new_bad[:10]:
        print(f'  BAD: {repr(r["extracted_value"])}')

# Check ADDRESS for prefixes
print(f'\n=== ADDRESS prefix check (NEW CSV) ===')
addr_rows = [r for r in new_rows if r['sensitive_type'] == 'ADDRESS']
print(f'ADDRESS total: {len(addr_rows)}')

# Bad prefixes to check
addr_bad_prefixes = ['客户', '收件', '寄件', '公司', '单位']
addr_with_bad_prefix = [r for r in addr_rows if any(r['extracted_value'].startswith(p) for p in addr_bad_prefixes)]
print(f'ADDRESS with bad prefixes: {len(addr_with_bad_prefix)}')
if addr_with_bad_prefix:
    for r in addr_with_bad_prefix[:5]:
        print(f'  BAD: {repr(r["extracted_value"][:30])}...')

# Sample ADDRESS values
print(f'\n=== ADDRESS samples ===')
for r in addr_rows[:10]:
    v = r['extracted_value']
    print(f'  {repr(v[:50])}...' if len(v) > 50 else f'  {repr(v)}')

# Sample CHINESE_NAME values
print(f'\n=== CHINESE_NAME samples (NEW) ===')
for r in new_name_rows[:20]:
    print(f'  {repr(r["extracted_value"])}')

# Database coverage
from collections import Counter
print(f'\n=== Database coverage (NEW) ===')
db_counts = Counter(r['db_name'] for r in new_rows)
for db, count in sorted(db_counts.items()):
    print(f'  {db}: {count}')
