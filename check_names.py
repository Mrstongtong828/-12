import csv

# 旧 CSV 检查坏模式
with open('output/upload_backup.csv', 'r', encoding='utf-8') as f:
    old_rows = list(csv.DictReader(f))

# 新 CSV 检查样本
with open('output/upload.csv', 'r', encoding='utf-8') as f:
    new_rows = list(csv.DictReader(f))

# 坏模式
bad_patterns = ['审计员', '警官', '专员', '公积金提']

print('=== Old CSV bad pattern check ===')
old_name_rows = [r for r in old_rows if r['sensitive_type'] == 'CHINESE_NAME']
old_bad = [r for r in old_name_rows if any(bp in r['extracted_value'] for bp in bad_patterns)]
print(f'CHINESE_NAME total: {len(old_name_rows)}')
print(f'With bad patterns: {len(old_bad)}')
for r in old_bad[:5]:
    print(f'  BAD: {repr(r["extracted_value"])}')

print()
print('=== New CSV CHINESE_NAME samples ===')
new_name_rows = [r for r in new_rows if r['sensitive_type'] == 'CHINESE_NAME']
for r in new_name_rows[:30]:
    print(f'  {repr(r["extracted_value"])}')
