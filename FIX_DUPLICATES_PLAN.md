# 修复 upload.csv 重复记录问题的实施方案

## 问题现状

- `upload.csv` 有 **25,441 条记录**，其中 **16,109 条是重复记录**（63.3%）
- 与参考文件 `example(6).csv`（572 条）对比，发现 **4 个根本原因**
- 需要修复后重新扫描生成干净的 upload.csv

---

## 四个根本原因及修复方案

### 原因 1：编码字段的多重扫描路径
**严重程度：** 🔴 中等
**影响：** 编码字段可能被步骤2（密码字段）+ 步骤6（非结构化）+ 步骤7（默认）多次处理

**修复方案：** 已部分修复（通过 FP 黑名单减少误报），无需额外改动

---

### 原因 2：非结构化文本的多源识别，仅在扫描器内部去重
**严重程度：** 🟡 中等
**影响：** 正则、UIE、姓名专项、地址专项可能发现同一信息

**修复方案：** 已通过 `_post_filter` 统一过滤，基本解决

---

### 原因 3：`record_id` 来源不稳定（最关键）
**严重程度：** 🔴 **最高**
**影响：** 全量扫描用真实主键，抽样扫描用序号 1-30，导致同一数据被识别为不同记录

**修复文件：** `main.py`

**具体修改：**

```python
# 位置：_sampled_rows 函数（第 76-160 行）
# 当前代码：
def _sampled_rows(conn, db_type: str, table_name: str, pk_col):
    ...
    seq = 0
    for where_order in segments:
        sql = f"SELECT * FROM {tbl} WHERE {where_order} LIMIT {per_segment}"
        for r in rows:
            seq += 1
            pk_value = r_dict.get(pk_col, seq)  # ⚠️ 无主键时用 seq
            yield (pk_value, r_dict)

# 修复后：
def _sampled_rows(conn, db_type: str, table_name: str, pk_col):
    ...
    seq = 0
    collected_pks = set()  # 跟踪已收集的主键，避免重复
    for where_order in segments:
        sql = f"SELECT * FROM {tbl} WHERE {where_order} LIMIT {per_segment}"
        for r in rows:
            seq += 1
            pk_value = r_dict.get(pk_col, seq)
            # 如果有真实主键，检查是否已收集过
            if pk_col and pk_value in collected_pks:
                continue  # 跳过重复行
            collected_pks.add(pk_value)
            yield (pk_value, r_dict)
```

**预期效果：** 消除抽样扫描中的记录重复，record_id 统一为真实主键值

---

### 原因 4：`CSVWriter` 去重键包含 `sensitive_type`
**严重程度：** 🔴 **最高**
**影响：** 同一敏感值（如 "13800138000"）被识别为不同类型（手机号 vs 身份证）时会写入两次

**修复文件：** `core/csv_writer.py`

**具体修改：**

```python
# 第 45-65 行：write_row 方法
# 当前去重键：
key = (
    db_type, db_name, table_name, field_name, record_id,
    str(row_dict.get("sensitive_type", "")),  # ❌ 包含敏感类型
    extracted_stripped,
)

# 修复后去重键：
key = (
    db_type, db_name, table_name, field_name, record_id,
    extracted_stripped,  # ✅ 只基于值去重，类型不同也视为重复
)
```

**副作用处理：**
- 同一值的多种类型标注会丢失，保留首次发现的类型
- 这符合去重需求，避免同一敏感信息被多次记录

**预期效果：** 消除因类型判断不一致导致的重复，减少 30-40% 记录数

---

## 综合修复方案

### 方案 A：分步修复（推荐）

**步骤 1：** 修改 `core/csv_writer.py` 去重键（原因 4）
**步骤 2：** 修改 `main.py` 的 `_sampled_rows` 去重（原因 3）
**步骤 3：** 重新运行扫描，生成新的 `upload.csv`
**步骤 4：** 验证与 `example(6).csv` 的格式和一致性

**优点：** 改动最小，针对性最强，风险可控

---

### 方案 B：全局去重（激进）

在 `main.py` 的 `_scan_table` 中添加全局 `seen` 集合，在写入 CSV 前统一检查：

```python
# 在 main.py 顶部添加
_global_seen = set()

# 修改 _scan_table 中的写入逻辑
def _scan_table(...):
    local_buffer = []
    for pk_value, row in row_iter:
        for field_name, value in row.items():
            findings = dispatch(...)
            for finding in findings:
                # 全局去重键（不含 sensitive_type）
                key = (
                    finding['db_type'], finding['db_name'],
                    finding['table_name'], finding['field_name'],
                    finding['record_id'], finding['extracted_value']
                )
                if key not in _global_seen:
                    _global_seen.add(key)
                    local_buffer.append(finding)
```

**优点：** 彻底解决所有重复问题
**缺点：** 需要传递共享状态，可能影响并发性能

---

## 建议执行顺序

1. ✅ **已完成：** FP 误报过滤优化（commit `4f14a2e`）
2. ⏭️ **待执行：** CSVWriter 去重键修复（原因 4）
3. ⏭️ **待执行：** `_sampled_rows` 去重优化（原因 3）
4. ⏭️ **待执行：** 重新扫描生成新的 upload.csv
5. ⏭️ **待执行：** 对比验证与 example(6).csv 的一致性

---

## 预期结果

修复完成后，期望：
- `upload.csv` 记录数从 **25,441 条** 降至 **3,000-5,000 条**（减少 80%+）
- 重复记录率从 **63.3%** 降至 **< 5%**
- 与 `example(6).csv` ��一致性显著提升
- `sensitive_type` 不一致的字段数从 490 个降至 < 50 个

---

## 风险提示

⚠️ **可能的影响：**
1. 去重键修改可能导致某些**真实的多类型敏感信息**被遗漏（如一个身份证号同时是 ID_CARD 和 BANK_CARD 关联）
2. 抽样扫描的 `record_id` 统一为真实主键后，可能需要调整后续处理逻辑
3. 重新扫描需要 **5-10 分钟**（取决于数据库大小）

✅ **缓解措施：**
- 保留原始 `upload.csv` 作为备份
- 先在小表上测试修复效果
- 对比修复前后与 `example(6).csv` 的差异

---

## 决策点

请选择：
- **A：** 执行方案 A（分步修复，先改 csv_writer.py，再改 main.py）
- **B：** 执行方案 B（全局去重，在 main.py 添加全局 seen 集合）
- **C：** 先生成去重后的 clean CSV，不修改代码
- **D：** 暂不修复，先分析其他问题
