# 说明

[toc]

## 一、快速开始

将收到的两个压缩包逐一加载到 Docker 本地镜像库：

```bash
docker load -i dasctf-mysql-2026.tar.gz
docker load -i dasctf-postgres-2026.tar.gz


# 在 docker-compose.yml 所在目录执行
docker-compose up -d

# 启动成功后验证
docker-compose ps

# 若想停止环境
docker-compose down
```

若两个容器均为 Up 状态即可。



## 二、数据库连接信息

| 引擎 | Host | Port | 用户名 | 密码 | 包含的数据库 |
|------|------|------|--------|------|------------|
| MySQL 8.0 | `127.0.0.1` | `3306` | `root` | `rootpass123` | `ecommerce_db`、`fintech_db` |
| PostgreSQL 15 | `127.0.0.1` | `5432` | `postgres` | `rootpass123` | `healthcare_db`、`govservice_db` |



## 三、提交格式

### 3.1 基础格式说明

提交文件名为 **`upload.csv`**，上传到验证靶机。

**每发现一条敏感数据即写一行**，CSV 含以下 9 列（无引号，UTF-8 编码）：

```
db_type,db_name,table_name,field_name,record_id,data_form,sensitive_type,sensitive_level,extracted_value
```

| 列名 | 类型 | 说明 |
|------|------|------|
| `db_type` | 枚举 | 值固定为 `mysql` 或 `postgresql` |
| `db_name` | 字符串 | 数据库名，如 `ecommerce_db` |
| `table_name` | 字符串 | 表名，与数据库中一致（大小写敏感） |
| `field_name` | 字符串 | 字段名，与数据库中一致（大小写敏感）；数据库对象填对象名 |
| `record_id` | 整数 | 该记录的主键值；数据库对象填 `—`（em 破折号） |
| `data_form` | 枚举 | 见下表，根据敏感值在数据库中的存储形态填写 |
| `sensitive_type` | 枚举 | 见下方第四节敏感类型表 |
| `sensitive_level` | 枚举 | `L1` / `L2` / `L3` / `L4` |
| `extracted_value` | 字符串 | **从数据库中实际提取到的原始敏感值**（精确匹配） |

**`data_form` 取值说明**：

| 值 | 含义 | 判断依据 |
|----|------|---------|
| `structured` | 结构化字段 | 敏感值直接存在普通字段中（字符串/数字类型） |
| `semi_structured` | 半结构化嵌套 | 字段存的是 JSON / JSONB / XML 字符串，敏感值藏在其内部节点里 |
| `encoded` | 编码/变形 | 字段值经过 Base64 / Hex / URL 编码等变换，解码后才是敏感值 |
| `unstructured_text` | 非结构化文本 | 字段是大段自然语言（日志、备注、案件描述等），需从中抽取敏感实体 |
| `binary_blob` | 二进制图片 | 字段是 BLOB / BYTEA / Base64 图片，需 OCR 识别图片中的文字 |
| `db_object` | 数据库对象 | 存储过程 / 视图的 SQL 定义中硬编码了敏感数据（非表记录） |

### 3.2 数据库对象特殊规则

除了普通表，还需要扫描**存储过程**和**视图**的定义代码——有时开发者会把密码、手机号等敏感信息直接硬编码在 SQL 代码里。

**第一步：查出所有存储过程 / 视图的名称**

MySQL：
```sql
-- 列出存储过程
SELECT ROUTINE_NAME FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA = '数据库名' AND ROUTINE_TYPE = 'PROCEDURE';

-- 列出视图
SELECT TABLE_NAME FROM information_schema.VIEWS
WHERE TABLE_SCHEMA = '数据库名';
```

PostgreSQL：
```sql
-- 列出存储过程 / 函数
SELECT proname FROM pg_proc
JOIN pg_namespace ON pg_namespace.oid = pg_proc.pronamespace
WHERE nspname = 'public';

-- 列出视图
SELECT table_name FROM information_schema.views
WHERE table_schema = 'public';
```

**第二步：查看其定义内容，识别其中的敏感值**

**第三步：上报时按如下规则填写**

| 字段 | 存储过程 | 视图 |
|------|---------|------|
| `table_name` | `__stored_procedure__` | `__view__` |
| `field_name` | 存储过程的名称（第一步查出来的） | 视图的名称（第一步查出来的） |
| `record_id` | `—`（em 破折号） | `—`（em 破折号） |

```
db_type,db_name,table_name,field_name,record_id,data_form,sensitive_type,sensitive_level,extracted_value
postgresql,govservice_db,__stored_procedure__,sp_sync_data,—,db_object,PASSWORD_OR_SECRET,L4,MyP@ssw0rd123
mysql,fintech_db,__view__,v_customer_summary,—,db_object,PHONE_NUMBER,L3,13800138000
```



### 3.3 示例行

```csv
db_type,db_name,table_name,field_name,record_id,data_form,sensitive_type,sensitive_level,extracted_value
mysql,ecommerce_db,user_profile,real_name,1,structured,CHINESE_NAME,L3,张三
mysql,ecommerce_db,user_profile,phone,1,structured,PHONE_NUMBER,L3,13800138000
mysql,ecommerce_db,order_ext_data,ext_json,201,semi_structured,BANK_CARD,L4,6222021234567890123
mysql,ecommerce_db,payment_detail,encoded_contact,305,encoded,PHONE_NUMBER,L3,13700137000
mysql,ecommerce_db,customer_feedback,feedback_content,412,unstructured_text,CHINESE_NAME,L3,王五
mysql,ecommerce_db,user_attachments,doc_image,518,binary_blob,ID_CARD,L4,440106199001011234
postgresql,govservice_db,__stored_procedure__,sp_sync_data,—,db_object,PASSWORD_OR_SECRET,L4,MyP@ssw0rd123
```



### 3.4 精确匹配规则

评分系统对每行做**七元组精确匹配**：

```
(db_type, db_name, table_name, field_name, record_id, sensitive_type, extracted_value)
```

- `extracted_value` 去除首尾空白后与答案做**字符串精确比较**
- 对于编码字段：需提交**解码后的原始明文**，不是编码字符串
- 对于 BLOB 图片：需提交 OCR 识别到的**图片上的文字**，不是 BLOB 二进制
- `sensitive_level` 不参与 TP 匹配，但影响额外的等级准确率得分
- 非敏感记录（噪声行）**不需要**出现在 csv 中；噪声行的字段值为 `N/A_数字` 形式，跳过即可



## 四、敏感类型参考

提交时 `sensitive_type` 必须使用下表中的**英文标识**（大写，下划线分隔）：

| 编号 | 英文标识 | 说明 | 级别 | 示例 |
|------|---------|------|------|------|
| 1 | `CHINESE_NAME` | 中文姓名 | L3 | 张三 |
| 2 | `PHONE_NUMBER` | 手机号码 | L3 | 13800138000 |
| 3 | `EMAIL` | 电子邮箱 | L3 | user@example.com |
| 4 | `ADDRESS` | 家庭住址 | L3 | 广东省广州市天河区XX路XX号 |
| 5 | `LICENSE_PLATE` | 车牌号 | L3 | 粤A12345 |
| 6 | `SOCIAL_SECURITY_NO` | 社保账号 | L3 | 粤SB20240001 |
| 7 | `HOUSING_FUND_NO` | 公积金账号 | L3 | GZ20240001234 |
| 8 | `MEDICAL_INSURANCE_NO` | 医保卡号 | L3 | YB44010620240001 |
| 9 | `VIN_CODE` | 车辆识别号(VIN) | L3 | LSVAU2180N2123456 |
| 10 | `MEDICAL_RECORD_NO` | 病历号/就诊号 | L3 | MR202400001 |
| 11 | `USCC` | 统一社会信用代码 | L3 | 91440101MA5EXAMPLE |
| 12 | `BUSINESS_LICENSE_NO` | 营业执照号 | L3 | 440106000123456 |
| 13 | `GPS_COORDINATE` | 经纬度坐标 | L2 | 23.1291, 113.2644 |
| 14 | `IP_ADDRESS` | IP 地址 | L2 | 192.168.1.100 |
| 15 | `MAC_ADDRESS` | MAC 地址 | L2 | 00:1A:2B:3C:4D:5E |
| 16 | `ID_CARD` | 身份证号 | L4 | 440106199001011234 |
| 17 | `BANK_CARD` | 银行卡号 | L4 | 6222021234567890123 |
| 18 | `PASSPORT` | 护照号码 | L4 | E12345678 |
| 19 | `MILITARY_ID` | 军官证号 | L4 | 军字第2024XXXX号 |
| 20 | `PASSWORD_OR_SECRET` | 密码/密钥/Token | L4 | sk-xxxx / $2b$10$... |



## 五、参考示例文件

随附的 **`example.csv`** 包含约 1% 的正确答案样本，覆盖全部六种数据形态，用途：

- 验证你的系统输出格式是否正确（字段顺序、枚举值拼写等）
- 快速对照自己的输出，确认特定数据形态是否被正确识别

---

## 六、评分规则

### 6.1 自动评分部分（占总分 50%）

靶机采用**分层加权 F1-Score** 机制（记录级精确匹配）。

#### ① 各数据形态 F1-Score

upload.csv 按 `data_form` 分组，对每种形态分别统计：

```
TP = 正确识别的该形态敏感条目数
FP = 错误识别的该形态敏感条目数（误报）
FN = 遗漏的该形态敏感条目数（漏报）

F1_form = 2 × Precision × Recall / (Precision + Recall)
        其中  Precision = TP/(TP+FP)，Recall = TP/(TP+FN)
```

> 匹配规则：需同时定位到正确的数据库、表、字段、记录，并正确提取敏感值原始内容。
> `sensitive_level` **不参与** TP 判断，仅在第③步单独评估。

#### ② 加权汇总 F1

| 数据形态 | 权重 |
|---------|------|
| `structured` | 0.10 |
| `semi_structured` | 0.20 |
| `encoded` | 0.20 |
| `unstructured_text` | 0.25 |
| `binary_blob` | 0.20 |
| `db_object` | 0.05 |

```
加权F1 = Σ(权重 × F1_form)
```

#### ③ 敏感等级准确率

在所有正确识别的条目中，统计 `sensitive_level` 填写正确且占答案总量的比例：

```
等级准确率 = 等级正确的TP数 / 答案总行数
```

#### ④ 综合识别得分（靶机返回此值）

```
综合识别得分 = 加权F1 × 0.70 + 等级准确率 × 0.30
```

#### ⑤ 性能指标得分（评审阶段跨队比较，靶机不返回）

```
时间得分 = 最短识别时间(s) / 当前队伍识别时间(s) × 100
CPU得分  = 最低CPU平均占用率 / 当前CPU平均占用率 × 100
内存得分 = 最低内存平均占用率 / 当前内存平均占用率 × 100
```

#### ⑥ 敏感信息识别准确度总得分

```
总得分 = 综合识别得分 × 0.75 + 时间得分 × 0.12 + CPU得分 × 0.08 + 内存得分 × 0.05
```

### 6.2 总评分维度

| 维度 | 权重 |
|------|------|
| 敏感信息识别准确度（含时间/资源得分） | 50% |
| 脱敏方案合理性 | 15% |
| 完成度（六种形态覆盖 + 脱敏 + 权限管控） | 15% |
| 研究报告质量 | 10% |
| 研究深度和广度 | 10% |

### 6.3 时间限制

程序需在 **30 分钟**内完成全部 4 个数据库的扫描、识别、分级分类，超时部分不计入评分。



## 七、提交物清单

| 文件 | 是否必须 |
|------|---------|
| `upload.csv` | ✅ 必须，上传至验证靶机自动评分 |
| 研究报告（PDF） | ✅ 必须，含系统架构、五种形态处理策略、脱敏方案、权限管控策略 |
| 系统源代码 | ✅ 必须，需可复现运行 |



## 八、常见问题

**Q：连接数据库时提示拒绝访问？**

A：确认容器已启动（`docker-compose ps` 均为 Up），且使用 `127.0.0.1` 而非 `localhost`（部分驱动行为不同）。



**Q：upload.csv 中的 `record_id` 怎么获取？**

A：每张表都有整数类型的主键列，直接读取该列值即可。



**Q：一条记录里有多个敏感值怎么提交？**

A：每个敏感值单独一行，`record_id` 相同但 `sensitive_type` 和 `extracted_value` 不同。



**Q：编码字段应该提交编码后的值还是解码后的值？**

A：提交**解码后的原始明文**（如手机号、银行卡号等）。



**Q：BLOB 图片字段里有多个敏感信息怎么处理？**

A：同一个 `(table_name, field_name, record_id)` 下，每个识别到的敏感值单独一行。



**Q：系统必须离线运行吗？**

A：是的，赛场无外网访问。OCR、NLP/NER 等能力需使用本地模型。

---

*所有赛题数据均为虚构生成，不含任何真实个人信息。*
