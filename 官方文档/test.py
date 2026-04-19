import pandas as pd

# 确保这里的 csv 文件名和你实际要分析的文件名一致
df = pd.read_csv('example(6).csv', encoding='utf-8')

print('=== 1. data_form 分布 ===')
print(df['data_form'].value_counts())

print()
print('=== 2. sensitive_type 分布 ===')
print(df['sensitive_type'].value_counts())

print()
print('=== 3. data_form × sensitive_type 交叉表 ===')
print(pd.crosstab(df['data_form'], df['sensitive_type']))

print()
print('=== 4. 每种 data_form 抽 8 行样例 ===')
for form in df['data_form'].unique():
    print(f'--- {form} ---')
    sample = df[df['data_form'] == form].head(8)
    for _, r in sample.iterrows():
        print(f'  [{r["db_name"]}.{r["table_name"]}.{r["field_name"]}] '
              f'{r["sensitive_type"]}({r["sensitive_level"]}) = {r["extracted_value"]!r}')
    print()