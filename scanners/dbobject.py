"""
数据库对象（存储过程/函数/触发器/视图）敏感信息扫描。

赛题规定的上报格式：
  - table_name 固定写 __stored_procedure__ 或 __view__
  - record_id 填 em-dash '—'
  - data_form 固定为 db_object

覆盖范围：
  MySQL:
    - PROCEDURE (information_schema.ROUTINES)
    - FUNCTION  (information_schema.ROUTINES)          ← 新增
    - TRIGGER   (information_schema.TRIGGERS)          ← 新增
    - VIEW      (SHOW CREATE VIEW，拿完整定义；fallback 到 VIEW_DEFINITION)

  PostgreSQL:
    - 所有业务 schema 的函数  (pg_proc + pg_get_functiondef)
    - 所有业务 schema 的视图  (information_schema.views + pg_get_viewdef)

赛题只规定了 __stored_procedure__ / __view__ 两种对象名。函数和触发器
本质都是可执行代码体，归到 __stored_procedure__ 处理（社区通行做法）。

错误隔离：每种对象类型独立 try/except；权限不足/驱动差异/对象不存在
都不会中断对其他对象的扫描。
"""
from core.patterns import extract_sensitive_from_value
from core.config import SENSITIVE_LEVEL_MAP

EM_DASH = "\u2014"


def _make_finding(db_type, db_name, obj_name, obj_kind, sensitive_type, extracted_value):
    """
    obj_kind 取值：
      'procedure' → table_name = __stored_procedure__
                    （适用于存储过程、函数、触发器）
      'view'      → table_name = __view__
    """
    table_name = "__stored_procedure__" if obj_kind == "procedure" else "__view__"
    level = SENSITIVE_LEVEL_MAP.get(sensitive_type, "L3")
    return {
        "db_type": db_type,
        "db_name": db_name,
        "table_name": table_name,
        "field_name": obj_name,
        "record_id": EM_DASH,
        "data_form": "db_object",
        "sensitive_type": sensitive_type,
        "sensitive_level": level,
        "extracted_value": extracted_value,
    }


def _scan_sql_text(obj_name, sql_text, obj_kind, db_type, db_name):
    """
    对一段 SQL 定义文本做敏感信息扫描。
    [dedup] 同一对象内同一 (type, value) 只记录一次——避免同一硬编码
    字符串在 SQL 里出现多次（如 SELECT + WHERE 都用到）被重复上报。
    """
    findings = []
    if not sql_text:
        return findings
    seen = set()
    for stype, val in extract_sensitive_from_value(sql_text):
        key = (stype, val)
        if key in seen:
            continue
        seen.add(key)
        findings.append(_make_finding(db_type, db_name, obj_name, obj_kind, stype, val))
    return findings


# ─────────────────────────── MySQL ───────────────────────────────

def _scan_mysql_routines(conn, db_type, db_name):
    """扫描 MySQL PROCEDURE + FUNCTION。"""
    findings = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ROUTINE_NAME, ROUTINE_TYPE, ROUTINE_DEFINITION "
                "FROM information_schema.ROUTINES "
                "WHERE ROUTINE_SCHEMA = %s "
                "  AND ROUTINE_TYPE IN ('PROCEDURE', 'FUNCTION')",
                (db_name,),
            )
            rows = cur.fetchall()
            for row in rows:
                # pymysql 默认用 DictCursor，但保留 tuple fallback 以防万一
                if isinstance(row, dict):
                    name = row.get("ROUTINE_NAME")
                    defn = row.get("ROUTINE_DEFINITION")
                else:
                    name, _rtype, defn = row[0], row[1], row[2]
                findings.extend(_scan_sql_text(name, defn, "procedure", db_type, db_name))
    except Exception as e:
        print(f"[ERROR] 扫描MySQL存储过程/函数失败 {db_name}: {e}")
    return findings


def _scan_mysql_triggers(conn, db_type, db_name):
    """扫描 MySQL TRIGGER。"""
    findings = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT TRIGGER_NAME, ACTION_STATEMENT "
                "FROM information_schema.TRIGGERS "
                "WHERE TRIGGER_SCHEMA = %s",
                (db_name,),
            )
            rows = cur.fetchall()
            # 诊断：当前连接对 TRIGGERS 表可能因缺少 TRIGGER 权限而拿到空结果
            if not rows:
                print(f"[INFO] MySQL {db_name} 未读到任何触发器（可能不存在或无权限）")
                return findings
            for row in rows:
                if isinstance(row, dict):
                    name = row.get("TRIGGER_NAME")
                    defn = row.get("ACTION_STATEMENT")
                else:
                    name, defn = row[0], row[1]
                findings.extend(_scan_sql_text(name, defn, "procedure", db_type, db_name))
    except Exception as e:
        print(f"[ERROR] 扫描MySQL触发器失败 {db_name}: {e}")
    return findings


def _scan_mysql_views(conn, db_type, db_name):
    """
    扫描 MySQL VIEW。
    information_schema.VIEWS.VIEW_DEFINITION 默认截断到 4KB，大视图会丢内容；
    优先用 SHOW CREATE VIEW 拿完整定义，失败时 fallback 到 VIEW_DEFINITION。
    """
    findings = []
    view_names = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT TABLE_NAME, VIEW_DEFINITION "
                "FROM information_schema.VIEWS "
                "WHERE TABLE_SCHEMA = %s",
                (db_name,),
            )
            for row in cur.fetchall():
                if isinstance(row, dict):
                    name = row.get("TABLE_NAME")
                    short_defn = row.get("VIEW_DEFINITION")
                else:
                    name, short_defn = row[0], row[1]
                view_names.append((name, short_defn))
    except Exception as e:
        print(f"[ERROR] 列出MySQL视图失败 {db_name}: {e}")
        return findings

    for name, short_defn in view_names:
        full_defn = None
        try:
            with conn.cursor() as cur:
                # 反引号转义视图名
                safe_name = name.replace("`", "``")
                cur.execute(f"SHOW CREATE VIEW `{safe_name}`")
                row = cur.fetchone()
                if row:
                    # SHOW CREATE VIEW 返回列：View, Create View, character_set_client, collation_connection
                    if isinstance(row, dict):
                        full_defn = row.get("Create View") or row.get("create view")
                    else:
                        # tuple 位置：[0]=View, [1]=Create View
                        full_defn = row[1] if len(row) > 1 else None
        except Exception as e:
            print(f"[WARN] SHOW CREATE VIEW 失败 {db_name}.{name}，fallback 到 VIEW_DEFINITION: {e}")

        defn = full_defn if full_defn else short_defn
        findings.extend(_scan_sql_text(name, defn, "view", db_type, db_name))

    return findings


# ───────────────────────── PostgreSQL ────────────────────────────

# 排除系统 schema；扫描所有业务 schema
_PG_EXCLUDED_SCHEMAS = (
    'pg_catalog', 'information_schema', 'pg_toast',
)


def _scan_pg_functions(conn, db_type, db_name):
    """扫描所有业务 schema 的函数定义。"""
    findings = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.proname, pg_get_functiondef(p.oid)
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname NOT IN %s
                  AND n.nspname NOT LIKE 'pg_%%'
                """,
                (_PG_EXCLUDED_SCHEMAS,),
            )
            for row in cur.fetchall():
                name, defn = row[0], row[1]
                findings.extend(_scan_sql_text(name, defn, "procedure", db_type, db_name))
    except Exception as e:
        print(f"[ERROR] 扫描PostgreSQL函数失败 {db_name}: {e}")
    return findings


def _scan_pg_views(conn, db_type, db_name):
    """
    扫描所有业务 schema 的视图定义。
    用 pg_get_viewdef(c.oid) 拿完整 SQL；oid 比 regclass 更健壮
    （视图名含点或特殊字符时 regclass 会报错）。
    """
    findings = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT c.relname, pg_get_viewdef(c.oid)
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relkind IN ('v', 'm')            -- v=普通视图, m=物化视图
                  AND n.nspname NOT IN %s
                  AND n.nspname NOT LIKE 'pg_%%'
                """,
                (_PG_EXCLUDED_SCHEMAS,),
            )
            for row in cur.fetchall():
                name, defn = row[0], row[1]
                findings.extend(_scan_sql_text(name, defn, "view", db_type, db_name))
    except Exception as e:
        print(f"[ERROR] 扫描PostgreSQL视图失败 {db_name}: {e}")
    return findings


def _scan_pg_triggers(conn, db_type, db_name):
    """
    扫描 PostgreSQL 触发器。PG 的触发器本身只是一个绑定——实际业务代码
    在它调用的那个函数里，已经被 _scan_pg_functions 覆盖。所以这里只扫
    触发器名称本身（有些开发者会把密码写在触发器名里，罕见但便宜）。
    如果扫描函数已经覆盖，这里即使什么都不做也不会漏报；
    谨慎起见打印一次观察性日志。
    """
    findings = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT t.tgname, pg_get_triggerdef(t.oid)
                FROM pg_trigger t
                JOIN pg_class c ON c.oid = t.tgrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE NOT t.tgisinternal
                  AND n.nspname NOT IN %s
                  AND n.nspname NOT LIKE 'pg_%%'
                """,
                (_PG_EXCLUDED_SCHEMAS,),
            )
            for row in cur.fetchall():
                name, defn = row[0], row[1]
                findings.extend(_scan_sql_text(name, defn, "procedure", db_type, db_name))
    except Exception as e:
        print(f"[ERROR] 扫描PostgreSQL触发器失败 {db_name}: {e}")
    return findings


# ────────────────────────── 入口 ─────────────────────────────────

def scan_db_objects(conn, db_type: str, db_name: str):
    """
    统一入口。每种对象类型独立 try/except（由下层函数保证），
    任何一类失败都不会阻塞其他类型的扫描。
    """
    findings = []

    if db_type == "mysql":
        findings.extend(_scan_mysql_routines(conn, db_type, db_name))   # procedure + function
        findings.extend(_scan_mysql_triggers(conn, db_type, db_name))   # trigger
        findings.extend(_scan_mysql_views(conn, db_type, db_name))      # view (SHOW CREATE VIEW)
    elif db_type == "postgresql":
        findings.extend(_scan_pg_functions(conn, db_type, db_name))     # function(含 procedure)
        findings.extend(_scan_pg_views(conn, db_type, db_name))         # view
        findings.extend(_scan_pg_triggers(conn, db_type, db_name))      # trigger

    return findings
