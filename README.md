# 数据库敏感字段识别与安全管控系统

2026年广东省大学生计算机设计大赛（网络与数据安全挑战赛）参赛作品

## 项目简介

本项目是一个数据库敏感数据智能识别与安全管控系统，能够连接MySQL和PostgreSQL数据库，对数据库中五种不同形态的数据进行全面扫描与分析，自动发现敏感信息并完成分级分类、脱敏方案设计和权限管控策略生成。

## 核心功能

- **多形态敏感数据穿透识别**：支持结构化字段、半结构化嵌套数据、编码/变形数据、非结构化自然语言文本、二进制图片/文档五种数据形态的敏感信息识别
- **智能分级分类**：参照《数据安全法》和GB/T 35273-2020标准，将敏感数据划分为L1-L4四个等级
- **脱敏方案设计**：针对不同数据形态设计合理的脱敏方案
- **权限管控策略**：基于敏感数据分布生成权限管控建议

## 目录结构

```
项目/
├── core/                    # 核心模块
│   ├── db_connector.py     # 数据库连接器
│   └── patterns.py         # 敏感数据模式定义
├── scanners/               # 扫描器模块
│   ├── structured.py      # 结构化字段扫描
│   ├── encoded.py         # 编码数据扫描
│   └── unstructured.py    # 非结构化文本扫描
├── models/                 # 模型文件
├── output/                 # 输出目录（结果文件）
├── scripts/                # 工具脚本
├── tests/                  # 测试文件
├── main.py                # 主程序入口
├── requirements.txt       # 依赖列表
└── README.md             # 项目说明（本文件）
```

## 快速开始

### 环境要求

- Python 3.11+
- MySQL / PostgreSQL 数据库
- 推荐在 Intel 酷睿10代 i5-10400、16G内存、Windows11 环境下运行

### 安装依赖

```bash
# 使用项目提供的脚本自动安装
python scripts/run_setup.py

# 或手动安装
python -m venv venv311
venv311\Scripts\activate
pip install -r requirements.txt
```

### 配置数据库连接

在项目根目录创建 `.env` 文件，配置数据库连接信息：

```env
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_password
MYSQL_DATABASE=testdb

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_password
POSTGRES_DATABASE=testdb
```

### 运行扫描

```bash
python main.py
```

扫描结果将保存到 `output/` 目录，包括：

- `result.csv` - 敏感字段识别结果
- `report.md` - 脱敏方案和权限管控建议

## 输出格式

### result.csv 字段说明

| 字段名 | 说明 | 示例 |
|--------|------|------|
| table_name | 表名 | user_info |
| column_name | 字段名 | phone |
| data_type | 数据类型 | 联系方式 |
| sensitivity_level | 敏感等级 | L3 |
| data_format | 数据形态 | 结构化字段 |
| confidence | 置信度 | 0.95 |
| sample_value | 示例值 | 13800138000 |

### 敏感数据类型编码

- **ID**: 身份标识
- **PHONE**: 电话号码
- **EMAIL**: 电子邮件
- **BANK_CARD**: 银行卡号
- **ID_CARD**: 身份证号
- **ADDRESS**: 地址信息
- **LOCATION**: 地理位置
- **PASSWORD**: 密码密钥
- **COOKIE**: Cookie信息
- **TOKEN**: 访问令牌

### 敏感等级说明

- **L1（公开级）**: 可对外公开的数据
- **L2（内部级）**: 仅限组织内部使用的数据
- **L3（���感级）**: 包含个人信息或商业秘密的数据
- **L4（高度敏感级）**: 涉及核心隐私或金融安全的数据

## 工具脚本

项目提供以下工具脚本，位于 `scripts/` 目录：

- `list_all_files.py` - 列出项目中所有脚本文件
- `list_dirs.py` - 列出所有目录结构
- `run_setup.py` - 自动化环境配置脚本

## 开发说明

### 添加新的扫描规则

1. 在 `core/patterns.py` 中定义新的敏感数据模式
2. 在对应扫描器中实现识别逻辑
3. 更新敏感数据类型编码映射

### 测试

```bash
python -m pytest tests/
```

## 注意事项

- 系统必须在离线环境下运行，不得调用在线API
- OCR识别功能使用本地模型，不依赖云端服务
- 所有数据处理均在本地完成，确保数据安全

## 许可证

本项目为2026年广东省大学生计算机设计大赛参赛作品，仅供学习交流使用。

## 赛题原文

赛题详细说明请参阅 [`docs/赛题说明.md`](docs/赛题说明.md)
