# 数据库敏感字段识别与安全管控系统

> 2026 年广东省大学生计算机设计大赛(网络与数据安全挑战赛)本科组参赛作品

一套面向 MySQL / PostgreSQL 的**离线**敏感数据穿透识别、分级分类、脱敏方案与权限管控生成系统。面对六种真实存储形态——结构化字段、JSON/XML 嵌套、多层编码、自然语言文本、二进制图片/文档、数据库对象——逐一路由到专用扫描器,并在 30 分钟内完成 4 个数据库的全量扫描。

---

## 目录

- [一、功能概览](#一功能概览)
- [二、系统架构](#二系统架构)
- [三、目录结构](#三目录结构)
- [四、快速开始](#四快速开始)
- [五、输出格式](#五输出格式)
- [六、六种数据形态处理策略](#六六种数据形态处理策略)
- [七、敏感类型与等级](#七敏感类型与等级)
- [八、性能优化](#八性能优化)
- [九、脱敏与权限管控](#九脱敏与权限管控)
- [十、本地评分与调试](#十本地评分与调试)
- [十一、常见问题](#十一常见问题)

---

## 一、功能概览

- **六形态穿透识别**:同时覆盖 `structured` / `semi_structured` / `encoded` / `unstructured_text` / `binary_blob` / `db_object`,根据值的特征自动路由到专用扫描器。
- **20 种敏感类型识别**:身份证、银行卡、手机号、邮箱、中文姓名、地址、车牌、VIN、USCC、医保/社保/公积金号、护照、军官证、GPS、IP/MAC、密码密钥等,内置校验函数(ID 校验码、Luhn、USCC 等)降低误报。
- **多层解码链**:对 Base64 / Hex / URL / Unicode 转义的嵌套编码递归解码,带深度 / 长度 / 循环自指 / 膨胀比四重熔断。
- **离线 OCR + 文档解析**:PaddleOCR v4 中文模型扫描图片,PyMuPDF 抽数字版 PDF 文本,python-docx / openpyxl 解析 Office 文档,扫描版 PDF 逐页转图回退到 OCR。
- **子进程化 OCR**:PaddleOCR 独立子进程运行,带超时、周期性重建、连续失败熔断,杜绝主进程段错误导致整轮扫描崩溃。
- **数据库对象审计**:扫存储过程、函数、触发器、视图定义代码,识别硬编码的敏感信息。
- **分级分类**:对齐 GB/T 35273-2020 与《数据安全法》,自动输出 L1–L4 等级。
- **脱敏工具**:20 种敏感类型对应的脱敏策略(保留前后缀掩码、SHA-256 哈希、哈希前缀展示等),支持批量对比。
- **本地评分器**:按赛题 §6 公式(分桶 F1 + 加权 + 等级准确率 + 综合识别得分)复现靶机评分,支持 FP/FN/form-mismatch 诊断。

---

## 二、系统架构

```
                ┌──────────────────────────────────┐
                │         main.py (入口)           │
                │  时间预算 / 串行调度 / 写 CSV    │
                └──────────────┬───────────────────┘
                               │
               ┌───────────────┼───────────────┐
               ▼               ▼               ▼
        db_connector      dispatcher       csv_writer
        (连 DB/流式读)   (嗅探 + 路由)   (去重 + flush)
                               │
        ┌──────────┬──────────┼──────────┬──────────┐
        ▼          ▼          ▼          ▼          ▼
   structured  encoded   unstructured  blob    dbobject
   (正则+校验) (递归解码) (正则+NER)  (OCR/文档) (SQL扫描)
                                          │
                                          ▼
                                  ocr_client ⇌ ocr_worker
                                  (主进程)    (子进程/PaddleOCR)
```

**分发逻辑**(`core/dispatcher.py`)按以下优先级嗅探值特征:

1. `bytes` → BLOB 扫描器
2. `\x` 开头十六进制串 / Base64 图片 → BLOB 扫描器
3. 字段名含密码密钥关键字 → 整值即为 `PASSWORD_OR_SECRET`
4. `{` / `[` 开头 → JSON 递归扫描
5. `<` 开头 → XML 递归扫描
6. 具编码特征 → 编码扫描器(递归解码后再分发)
7. 字段名强提示结构化(real_name / phone / address / id_card 等) → 结构化扫描器
8. 长自然语言文本 → 非结构化扫描器
9. 默认 → 结构化扫描器

---

## 三、目录结构

```
项目/
├── core/                          # 核心模块
│   ├── config.py                  # 时间预算、抽样阈值、并发、BLOB 行数等参数
│   ├── db_connector.py            # 连接 MySQL/PostgreSQL,流式读取,主键嗅探
│   ├── dispatcher.py              # 值特征嗅探与扫描器路由
│   ├── patterns.py                # 正则、姓名词典、校验函数、地址清洗
│   ├── csv_writer.py              # 输出列定义、去重键、实时 flush
│   ├── task_queue.py              # AI 推理信号量(限流保护 OCR/UIE)
│   ├── logger.py                  # rich 进度条 + 文件错误日志
│   └── masking-tool.py            # 20 种脱敏策略 + 批量对比
├── scanners/                      # 扫描器模块
│   ├── structured.py              # 结构化 + JSON/XML 解析
│   ├── encoded.py                 # Base64/Hex/URL/Unicode 递归解码链
│   ├── unstructured.py            # 自然语言(正则 + 姓氏锚点 + UIE 可选)
│   ├── blob.py                    # PDF / DOCX / XLSX / 图片分发
│   ├── ocr_client.py              # OCR 主进程客户端(熔断 + 超时)
│   ├── ocr_worker.py              # OCR 子进程(PaddleOCR v4 中文模型)
│   └── dbobject.py                # 存储过程 / 函数 / 触发器 / 视图扫描
├── scripts/                       # 环境与辅助脚本
├── tests/                         # 测试目录(存放 example.csv 用于本地评分)
├── output/                        # upload.csv 输出目录
├── docker数据库启动/              # 赛题数据库容器启动文件
├── 官方文档/                      # 赛题原文 README
├── docs/赛题说明.md               # 赛题正文
├── main.py                        # 主程序入口
├── local_scorer.py                # 本地评分器(对齐官方公式)
├── diff-script.py                 # upload vs example 差异分析
├── requirements.txt               # 依赖列表
└── README.md                      # 本文件
```

---

## 四、快速开始

### 4.1 环境要求

- **OS**:Windows 11(赛题官方机型),也可在 Linux / macOS 运行
- **硬件**:Intel i5-10400 / 16GB RAM / CPU only(无需 GPU)
- **Python**:3.11+
- **数据库**:MySQL 8.0 与 PostgreSQL 15(赛题提供容器镜像)

### 4.2 安装依赖

```bash
# 创建虚拟环境
python -m venv venv311
venv311\Scripts\activate        # Windows
# source venv311/bin/activate   # Linux/macOS

# 安装依赖
pip install -r requirements.txt
```

**可选依赖**(具备时自动启用,不具备时静默降级):

- `pymupdf` → PDF 文本直接抽取
- `python-docx` → DOCX 解析
- `openpyxl` → XLSX 解析

### 4.3 下载离线模型

PaddleOCR v4 中文模型放到 `./models/paddleocr/` 下:

```
models/
└── paddleocr/
    ├── ch_PP-OCRv4_det_infer/       # 检测
    ├── ch_PP-OCRv4_rec_infer/       # 识别
    └── ch_ppocr_mobile_v2.0_cls_infer/  # 方向分类
```

UIE NER 模型(可选)放到 `./models/paddlenlp/uie-base/`,默认关闭,通过 `UIE_ENABLED=1` 开启。

### 4.4 启动比赛数据库

```bash
cd docker数据库启动
docker load -i dasctf-mysql-2026.tar.gz
docker load -i dasctf-postgres-2026.tar.gz
docker-compose up -d
docker-compose ps    # 两个容器都应为 Up
```

默认连接信息(`core/config.py`):

| 引擎        | Host      | Port | 用户     | 密码          | 数据库                        |
| ----------- | --------- | ---- | -------- | ------------- | ----------------------------- |
| MySQL 8.0   | 127.0.0.1 | 3306 | root     | rootpass123   | ecommerce_db / fintech_db     |
| PostgreSQL  | 127.0.0.1 | 5432 | postgres | rootpass123   | healthcare_db / govservice_db |

也可通过环境变量 `DB_PASSWORD` 覆盖密码。

### 4.5 运行扫描

```bash
python main.py
```

终端会显示 rich 进度条(每个库一行,实时展示扫描表名、累计行数、命中数、用时)。结果写入 `output/upload.csv`,每识别一条敏感信息即实时 flush,防止进程崩溃丢失。

环境变量(可选):

| 变量                  | 默认 | 说明                                 |
| --------------------- | ---- | ------------------------------------ |
| `USE_RICH_PROGRESS`   | 1    | 0 = 降级为 plain print               |
| `UIE_ENABLED`         | 0    | 1 = 启用 UIE NER(合并结果)          |
| `UIE_AUDIT`           | 0    | 1 = UIE 只打日志不合并(对比用)      |
| `DB_PASSWORD`         | —    | 覆盖默认数据库密码                    |

---

## 五、输出格式

`output/upload.csv` 共 9 列,UTF-8 无 BOM:

```
db_type,db_name,table_name,field_name,record_id,data_form,sensitive_type,sensitive_level,extracted_value
```

示例:

```csv
mysql,ecommerce_db,user_profile,phone,1,structured,PHONE_NUMBER,L3,13800138000
mysql,ecommerce_db,order_ext_data,ext_json,201,semi_structured,BANK_CARD,L4,6222021234567890123
mysql,ecommerce_db,payment_detail,encoded_payload,305,encoded,PHONE_NUMBER,L3,13700137000
postgresql,healthcare_db,consultation_notes,note_text,412,unstructured_text,CHINESE_NAME,L3,王五
mysql,fintech_db,kyc_verification,doc_image,518,binary_blob,ID_CARD,L4,440106199001011234
postgresql,govservice_db,__stored_procedure__,sp_sync_data,—,db_object,PASSWORD_OR_SECRET,L4,MyP@ssw0rd123
```

**去重规则**(`core/csv_writer.py`):同一 `(db_type, db_name, table_name, field_name, record_id, sensitive_type, extracted_value)` 组合只保留一条,避免同值被不同扫描路径重复命中。

**噪声过滤**:`N/A_数字` 形式的占位值、空串、占位符 `[xxx]` 一律跳过。

**数据库对象特殊规则**(赛题规定):

- 存储过程/函数/触发器 → `table_name = "__stored_procedure__"`,`field_name = 对象名`,`record_id = "—"`(em 破折号)
- 视图 → `table_name = "__view__"`,其余同上

---

## 六、六种数据形态处理策略

### 6.1 `structured`(结构化字段)

- 字段名正则命中敏感类型关键字(real_name / phone / id_card 等) → 直接按对应类型处理
- 含校验位的类型(ID_CARD、USCC、BANK_CARD)强制校验校验位
- BANK_CARD:Luhn 校验通过直接接受;不通过但符合 16/19 位 + 合法首位的,保留(救回伪造数据集的合理命中)
- 姓名识别三档:
  - 首选 4 字(含复姓),末尾溢出保护(`xxx先生` → 取 `xxx`)
  - 回退 3 字,检测 3 字末字 + 下一字是否构成动词 bigram(防 `刘跟进` → 误取 `刘跟`)
  - 结构化强匹配字段 + 纯中文 2–4 字 → 宽松路径救回 2 字名(居晸、曾榜、魏晴)

### 6.2 `semi_structured`(JSON / XML)

- `json.loads` / `ElementTree.fromstring` 递归遍历
- 叶子节点若为编码值,递归进入解码链
- 叶子节点过长(>5KB)截断再扫,防 OOM
- 同一节点的 key 作为"有效字段名"参与黑名单判断(`{"handler":"张警官"}` 不会被误识别为姓名)
- 数字类型叶子也扫描(防 `{"phone": 13800138000}` 漏抓)

### 6.3 `encoded`(编码/变形)

- 字段名含 `encoded_` / `payload` / `base64` / `cipher` 等强提示时,无条件递归解码(绕过启发式)
- 否则启发式:Base64 / Hex 解码后需"看起来有价值"(含中文或命中强 pattern)才视为编码
- 递归解码链支持 URL / Base64(含 URL-safe) / Hex / `\uXXXX` 转义,最多 5 轮
- 四重熔断:深度 > 5、单步长度 > 200KB、循环自指、累计膨胀比 > 10
- 解码后结果若仍是 JSON/XML,交给对应扫描器处理,最终 `data_form` 重标为 `encoded`
- Base64 图片(魔数 JPEG/PNG/GIF/BMP/WebP)自动路由到 BLOB 扫描器

### 6.4 `unstructured_text`(非结构化文本)

- 基线:正则扫描所有敏感类型
- 中文姓名:姓氏词典 + 复姓表 + 2 字名触发词上下文(`客户翟琸反映` / `居黎咨询`)
- 地址:正则命中后调用 `clean_address_prefix` 剥掉 `我家在/家住/现居/...` 前缀
- UIE NER(可选):schema 裁剪到 4 种强结构先验实体(手机/身份证/银行卡/邮箱),按 500 字分块推理,AI 信号量限流
- 后置过滤:
  - 字段名黑名单(`handler` / `operator` / `reviewer` 等)跳过 CHINESE_NAME
  - 称谓/职务后缀(`xxx警官` / `xxx女士` / `xxx医生`)跳过
  - IP 后紧跟 CIDR(`/24`)或版本号模式(`v1.2.3.4.5`)剔除
  - EMAIL 无合法 TLD 剔除

### 6.5 `binary_blob`(二进制图片/文档)

文件魔数嗅探后五路分发:

| 类型    | 魔数                    | 处理方式                              |
| ------- | ----------------------- | ------------------------------------- |
| PDF     | `%PDF`                  | PyMuPDF 先抽数字文本,空则逐页转图 OCR |
| DOCX    | `PK` + `word/`          | python-docx 抽段落 + 表格             |
| XLSX    | `PK` + `xl/`            | openpyxl 抽所有单元格                 |
| 图片    | JPEG/PNG/GIF/BMP/WebP   | OCR 子进程                            |
| UNKNOWN | —                       | 兜底走 OCR                            |

OCR 路径额外做:
- **预处理**:合并被空格切碎的长数字串(`440106 19900101 1234` → 18 位身份证)、规整 label 冒号
- **数字类纠错**:O→0、I→1、S→5 等,只作用于长数字串(≥6 位混合字符)
- **双路径扫描**:原文本 + 纠错后文本各扫一次,合并去重

### 6.6 `db_object`(数据库对象)

- **MySQL**:`information_schema.ROUTINES`(PROCEDURE + FUNCTION)、`information_schema.TRIGGERS`、`SHOW CREATE VIEW`(视图拿完整定义,fallback 到 `VIEW_DEFINITION`)
- **PostgreSQL**:`pg_proc + pg_get_functiondef`、`pg_get_viewdef`、`pg_get_triggerdef`,排除系统 schema
- 每种对象独立 try/except,权限不足 / 驱动差异不会阻塞其他对象的扫描
- 对象内去重:同一 (type, value) 只记录一次,避免同一硬编码串在 SQL 中出现多次被多次上报

---

## 七、敏感类型与等级

20 种敏感类型严格对齐赛题规范:

| 等级 | 类型                                                                                     |
| ---- | ---------------------------------------------------------------------------------------- |
| L2   | GPS_COORDINATE、IP_ADDRESS、MAC_ADDRESS                                                  |
| L3   | CHINESE_NAME、PHONE_NUMBER、EMAIL、ADDRESS、LICENSE_PLATE、SOCIAL_SECURITY_NO、HOUSING_FUND_NO、MEDICAL_INSURANCE_NO、VIN_CODE、MEDICAL_RECORD_NO、USCC、BUSINESS_LICENSE_NO |
| L4   | ID_CARD、BANK_CARD、PASSPORT、MILITARY_ID、PASSWORD_OR_SECRET                             |

等级映射集中在 `core/config.py` 的 `SENSITIVE_LEVEL_MAP`。等级划分参照《数据安全法》与 GB/T 35273-2020:

- **L1 公开级**:可对外公开
- **L2 内部级**:仅限组织内部使用
- **L3 敏感级**:个人信息或商业秘密
- **L4 高度敏感级**:核心隐私或金融安全

---

## 八、性能优化

为在 30 分钟内稳定扫完 4 个数据库,在 16GB 官方机型上做了一系列针对性优化:

| 维度         | 策略                                                                              |
| ------------ | --------------------------------------------------------------------------------- |
| 总时间预算   | 30 分钟硬时限,单表 300s 预算,超时即 break 继续下一张表                            |
| 大表保护     | 行数估算(MySQL `TABLE_ROWS` / PG `reltuples`)> 5 万启用分层抽样(头/中/尾三段) |
| BLOB 表保护  | 含 BLOB/BYTEA 列的表限扫 400 行,且排到所有普通表之后,防 OCR 熔断影响其他形态     |
| 并发         | `DB_WORKERS=1` 主线程串行(避开 PaddleOCR + 多线程 + Windows 段错误组合拳)      |
| OCR 隔离     | PaddleOCR 独立子进程,25s 单图超时 + 连续失败 5 次熔断 + 周期性重建(16 张一次)  |
| 内存控制     | `FLAGS_fraction_of_cpu_memory_to_use=0.25`(主) / `0.5`(OCR 子进程)            |
| 网络读取     | MySQL/PG 流式 cursor,每次 fetchmany 500 行,避免一次性 load 全表                 |
| 编码修复     | MySQL mojibake(`cp1252` → `utf-8` 二次还原)仅对含中文的结果生效                 |
| CSV 实时落盘 | 每条命中即 flush,进程崩溃也不丢数据                                               |
| 去重提前     | 写入层按 7 元组去重,扫描链前置无需判重                                            |

---

## 九、脱敏与权限管控

### 9.1 脱敏方案

`core/masking-tool.py` 为 20 种敏感类型各配一条策略,核心设计:

- **L4 核心隐私**:强脱敏(大部分位掩码)或 SHA-256 不可逆哈希(密码类)
- **L3 个人信息**:保留前后少量位(前 3 后 4、前 6 后 4 等)
- **L2 设备标识**:保留网段/厂商 OUI/经纬度整数位

脱敏策略覆盖(摘要):

| 类型                 | 脱敏示例                                         |
| -------------------- | ------------------------------------------------ |
| PHONE_NUMBER         | `13812345678` → `138****5678`                    |
| ID_CARD              | `440106199001011234` → `440106********1234`       |
| BANK_CARD            | `6222021234567890123` → `6222***********0123`    |
| CHINESE_NAME         | `张三` → `张*` / `仲孙歌阑` → `仲孙**`            |
| EMAIL                | `alice@qq.com` → `a****@qq.com`                  |
| ADDRESS              | `广东省广州市...` → `广东省广州市****`           |
| IP_ADDRESS           | `192.168.1.100` → `192.168.*.*`                  |
| MAC_ADDRESS          | `76:c9:f9:d3:e1:c5` → `76:c9:f9:**:**:**`        |
| GPS_COORDINATE       | `23.1291,113.2644` → `23.*, 113.*`               |
| PASSWORD_OR_SECRET   | 原文 → `[SHA256:abcdef1234567890...]`            |
| MILITARY_ID          | 原文 → `[MILITARY_REDACTED]`(涉密全遮蔽)        |

**批量对比**:

```bash
python -m core.masking-tool                           # 处理 output/upload.csv → output/masked_report.csv
python -m core.masking-tool PHONE_NUMBER 13812345678  # 单值测试
```

输出的对比 CSV 在原 9 列之后追加 `masked_value` 与 `mask_strategy`,用于研究报告展示。

### 9.2 权限管控(设计思路)

基于敏感数据分布,按"角色 × 等级 × 操作"矩阵推导:

- **数据管理员**:可读 L1–L3 明文,L4 强制动态脱敏,导出需审批
- **业务人员**:L1 明文,L2–L3 部分脱敏,L4 不可见
- **审计人员**:全量可读但记录日志,禁止导出
- **外部服务**:仅 L1 + 脱敏后 L2

动态脱敏策略与扫描结果联动:每张表的敏感字段元数据写入策略中心,查询层按角色自动应用对应脱敏函数。

---

## 十、本地评分与调试

### 10.1 本地评分器

准备 `tests/example.csv`(赛题提供的约 1% 答案样本)后:

```bash
python local_scorer.py                              # 完整报告
python local_scorer.py --diff                       # 打印 FP/FN 明细
python local_scorer.py --diff --form encoded        # 只看 encoded 形态
python local_scorer.py --form-mismatch              # 看值对但 data_form 标错的
python local_scorer.py --normalize                  # NFKC+casefold 归一化
python local_scorer.py --strict-scope               # 3 元组 scope(调试用)
```

严格复现官方公式(README §6.1):

```
F1_form       = 2·P·R / (P + R)
加权F1         = Σ(权重 × F1_form)
等级准确率     = 等级正确的TP数 / 答案总行数
综合识别得分   = 加权F1 × 0.70 + 等级准确率 × 0.30   ← 对应靶机返回值
```

报告额外给出**本地天花板**(因 example.csv 未覆盖某些形态,本地完美预测也拿不到满分)和 **value-only F1**(忽略 data_form,诊断值找对但 form 标错的双重扣分问题)。

### 10.2 差异分析

```bash
python diff-script.py
```

对照 `output/upload.csv` vs `example6.csv`,按形态 / 类型分组列出 FN 全量清单、FP top-20 字段名、分层 F1、等级准确率等,定位回归点。

### 10.3 日志

- **终端**:rich 实时进度条(扫描表名、行数、命中数、耗时)
- **文件**:`scan_error.log` 收集 WARNING/ERROR,不污染终端
- **UIE 审计**:`UIE_AUDIT=1` 时 UIE 输出写入日志文件,供与正则基线对比

---

## 十一、常见问题

**Q:扫描中途 PaddleOCR 段错误导致进程崩溃?**

A:已通过子进程隔离 + 超时 + 熔断规避。若仍出现,检查 `OMP_NUM_THREADS` / `MKL_NUM_THREADS` 是否在 `import numpy/cv2/paddle` 之前被设置为 `1`(`main.py` 与 `ocr_worker.py` 开头已处理)。

**Q:`output/upload.csv` 中出现大量重复记录?**

A:v3 去重键已简化为 7 元组精确匹配(位置 + 类型 + 值),仅删除重复上报,同一值的多种类型标注保留首次发现。若仍存在,检查是否抽样扫描与全量扫描混用导致 `record_id` 不稳定。

**Q:BLOB 表扫了但几乎没命中?**

A:确认 PaddleOCR 模型已下载到 `./models/paddleocr/` 且三个子模型目录齐全。观察 `scan_error.log` 中是否有 `[OCR] 连续失败 5 次,禁用 OCR` 告警,若有需检查图片尺寸是否超出处理上限(自动压缩到 ≤ 800px 长边)。

**Q:UIE 要不要开?**

A:默认关。UIE 对人名 / 地址的准确率不稳定,正则 + 姓氏词典已能吃掉大部分 recall。想试验可先用 `UIE_AUDIT=1` 看 UIE 会加多少 FP/TP,再决定是否 `UIE_ENABLED=1`。

**Q:如何添加新的敏感类型?**

A:三步走:
1. `core/patterns.py` 添加 `REGEX_PATTERNS["NEW_TYPE"]` 与可选的校验函数
2. `core/config.py` 的 `SENSITIVE_LEVEL_MAP` 补等级
3. `core/masking-tool.py` 的 `MASK_STRATEGY` 补脱敏策略(可选)

**Q:中文在 Windows 终端乱码?**

A:开 `chcp 65001` 切 UTF-8,或设置 `PYTHONIOENCODING=utf-8`。

---

## 赛题文档

详见 [`docs/赛题说明.md`](docs/赛题说明.md) 与 [`官方文档/README.md`](官方文档/README.md)。

## 许可证

2026 年广东省大学生计算机设计大赛参赛作品,仅供学习交流使用。所有赛题数据均为虚构生成,不含任何真实个人信息。
