import csv

# 读取两个CSV文件
example_file = r"e:\数据库敏感字段识别与安全管控系统\项目\output\example(6).csv"
upload_file = r"e:\数据库敏感字段识别与安全管控系统\项目\output\upload.csv"

print("=" * 80)
print("CSV文件格式一致性检查")
print("=" * 80)

# 读取表头
with open(example_file, 'r', encoding='utf-8') as f:
    example_reader = csv.reader(f)
    example_header = next(example_reader)
    print(f"example.csv 表头: {example_header}")

with open(upload_file, 'r', encoding='utf-8') as f:
    upload_reader = csv.reader(f)
    upload_header = next(upload_reader)
    print(f"upload.csv 表头: {upload_header}")

print(f"\n表头是否一致: {example_header == upload_header}")

# 读取所有数据行（使用字段组合作为唯一键）
def read_records(filepath):
    records = {}
    duplicates = []
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # 创建唯一键：数据库类型+表名+字段名+记录ID
            key = (row['db_type'], row['table_name'], row['field_name'], row['record_id'])
            if key in records:
                duplicates.append(key)
            else:
                records[key] = row
    return records, duplicates

print("\n正在读取 example(6).csv ...")
example_records, example_dupes = read_records(example_file)
print(f"  总记录数: {len(example_records)}")
if example_dupes:
    print(f"  重复记录: {len(example_dupes)} 条")
    for d in example_dupes[:5]:
        print(f"    {d}")

print("\n正在读取 upload.csv ...")
upload_records, upload_dupes = read_records(upload_file)
print(f"  总记录数: {len(upload_records)}")
if upload_dupes:
    print(f"  重复记录: {len(upload_dupes)} 条")
    for d in upload_dupes[:5]:
        print(f"    {d}")

# 检查重叠的记录
common_keys = set(example_records.keys()) & set(upload_records.keys())
print(f"\n两个文件重复的记录数: {len(common_keys)}")

if common_keys:
    print("\n检查重复记录是否一致:")
    mismatches = []
    for key in common_keys:
        example_row = example_records[key]
        upload_row = upload_records[key]
        # 比较除record_id外的其他字段
        for field in ['db_type', 'table_name', 'field_name', 'data_form', 'sensitive_type', 'sensitive_level', 'extracted_value']:
            if example_row[field] != upload_row[field]:
                mismatches.append((key, field, example_row[field], upload_row[field]))

    if mismatches:
        print(f"  发现 {len(mismatches)} 处不一致:")
        for key, field, ex_val, up_val in mismatches[:10]:
            print(f"    {key} - {field}: example='{ex_val}' vs upload='{up_val}'")
    else:
        print("  ✅ 所有重复记录完全一致！")

# 统计敏感类型分布
print("\n" + "=" * 80)
print("敏感类型分布对比:")
print("=" * 80)

def count_sensitive_types(records):
    counts = {}
    for record in records.values():
        stype = record['sensitive_type']
        counts[stype] = counts.get(stype, 0) + 1
    return counts

example_counts = count_sensitive_types(example_records)
upload_counts = count_sensitive_types(upload_records)

all_types = sorted(set(example_counts.keys()) | set(upload_counts.keys()))
print(f"{'类型':<20} {'example(6).csv':<15} {'upload.csv':<15}")
print("-" * 60)
for stype in all_types:
    ex = example_counts.get(stype, 0)
    up = upload_counts.get(stype, 0)
    marker = "=" if ex == up else "!"
    print(f"{stype:<20} {ex:<15} {up:<15} {marker}")

print("\n" + "=" * 80)
print("检查完成！")
print("=" * 80)
