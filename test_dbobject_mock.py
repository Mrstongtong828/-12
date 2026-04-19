"""
dbobject.py 本地 mock 测试
─────────────────────────
不需要启动 docker。用假连接模拟 MySQL/PostgreSQL 的 cursor 行为，
返回预置的 SQL 文本，验证：
  1. 能正确识别埋在 SQL 里的敏感值（phone/id_card/bank_card/email/password）
  2. 输出格式正确（table_name/field_name/record_id/data_form）
  3. 同一对象内重复值去重
  4. FUNCTION/TRIGGER 都被扫到
  5. PG 多 schema 扫描
  6. SHOW CREATE VIEW fallback 逻辑
  7. 错误隔离（某类对象查询失败不影响其他）

用法：
    python test_dbobject_mock.py
"""
import sys
import os

# ── 让测试脚本找到项目的 core / scanners 包 ──────────────────────
# 如果你的项目根是 E:/数据库敏感字段识别与安全管控系统/项目/
# 把本文件放到项目根里运行即可。否则调整下面的 PROJECT_ROOT。
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from scanners.dbobject import scan_db_objects  # noqa: E402


# ═══════════════════════════════════════════════════════════════
# Mock 连接/游标基础设施
# ═══════════════════════════════════════════════════════════════

class FakeCursor:
    """
    假 cursor。构造时传入 {sql_pattern: rows_list} 字典。
    execute 时根据 SQL 里的关键字匹配，fetchall/fetchone 返回预设数据。
    """
    def __init__(self, routes, dict_mode=False):
        self.routes = routes
        self.dict_mode = dict_mode
        self._current_rows = []
        self._current_idx = 0

    def execute(self, sql, params=None):
        # 根据 SQL 关键字路由到预设数据
        for key, rows in self.routes.items():
            if key in sql:
                # 处理 callable：允许路由返回一个函数（比如要抛异常的场景）
                if callable(rows):
                    self._current_rows = rows(sql, params)
                else:
                    self._current_rows = rows
                self._current_idx = 0
                return
        self._current_rows = []
        self._current_idx = 0

    def fetchall(self):
        rows = self._current_rows
        self._current_rows = []
        return rows

    def fetchone(self):
        if self._current_idx < len(self._current_rows):
            row = self._current_rows[self._current_idx]
            self._current_idx += 1
            return row
        return None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class FakeMySQLConn:
    """假 pymysql 连接。cursor 默认是 DictCursor 模式。"""
    def __init__(self, routes):
        self.routes = routes

    def cursor(self):
        return FakeCursor(self.routes, dict_mode=True)


class FakePGConn:
    """假 psycopg2 连接。cursor 返回 tuple。"""
    def __init__(self, routes):
        self.routes = routes

    def cursor(self, cursor_factory=None):
        return FakeCursor(self.routes, dict_mode=False)


# ═══════════════════════════════════════════════════════════════
# 工具函数
# ═══════════════════════════════════════════════════════════════

def assert_finding(findings, **expected):
    """检查 findings 里至少有一条匹配 expected 给出的所有字段。"""
    for f in findings:
        if all(f.get(k) == v for k, v in expected.items()):
            return True
    print(f"  ❌ 未找到期望的 finding: {expected}")
    print(f"     实际 findings:")
    for f in findings:
        print(f"       {f}")
    return False


def count_findings(findings, **match):
    return sum(1 for f in findings if all(f.get(k) == v for k, v in match.items()))


# ═══════════════════════════════════════════════════════════════
# 测试用例
# ═══════════════════════════════════════════════════════════════

PASSED = []
FAILED = []


def run(name, fn):
    try:
        fn()
        print(f"  ✅ {name}")
        PASSED.append(name)
    except AssertionError as e:
        print(f"  ❌ {name}: {e}")
        FAILED.append((name, str(e)))
    except Exception as e:
        print(f"  💥 {name}: {type(e).__name__}: {e}")
        FAILED.append((name, f"{type(e).__name__}: {e}"))


# ── TEST 1: MySQL PROCEDURE 基础识别 ─────────────────────────────
def test_mysql_procedure_basic():
    routes = {
        # _scan_mysql_routines 的 SQL
        "information_schema.ROUTINES": [
            {
                "ROUTINE_NAME": "sp_send_notice",
                "ROUTINE_TYPE": "PROCEDURE",
                "ROUTINE_DEFINITION":
                    "BEGIN "
                    "  SET @admin_phone = '13812345678'; "
                    "  SET @admin_email = 'admin@example.com'; "
                    "  -- 身份证号 440106199001011235 (合法校验码) "
                    "END",
            },
        ],
        "information_schema.TRIGGERS": [],
        "information_schema.VIEWS": [],
    }
    conn = FakeMySQLConn(routes)
    findings = scan_db_objects(conn, "mysql", "testdb")

    assert assert_finding(findings,
        db_type="mysql", db_name="testdb",
        table_name="__stored_procedure__", field_name="sp_send_notice",
        sensitive_type="PHONE_NUMBER", extracted_value="13812345678",
        data_form="db_object", record_id="\u2014"), "手机号未识别"

    assert assert_finding(findings,
        sensitive_type="EMAIL", extracted_value="admin@example.com"), "邮箱未识别"

    assert assert_finding(findings,
        sensitive_type="ID_CARD", extracted_value="440106199001011235"), "身份证未识别"


# ── TEST 2: MySQL FUNCTION 被扫到（图片里的第 1 个改进点）─────────
def test_mysql_function_covered():
    routes = {
        "information_schema.ROUTINES": [
            {
                "ROUTINE_NAME": "fn_get_card",
                "ROUTINE_TYPE": "FUNCTION",  # ← 注意是 FUNCTION 不是 PROCEDURE
                "ROUTINE_DEFINITION":
                    "RETURN '6222021234567890128';",
            },
        ],
        "information_schema.TRIGGERS": [],
        "information_schema.VIEWS": [],
    }
    conn = FakeMySQLConn(routes)
    findings = scan_db_objects(conn, "mysql", "testdb")

    assert assert_finding(findings,
        table_name="__stored_procedure__",  # 函数也归到 __stored_procedure__
        field_name="fn_get_card",
        sensitive_type="BANK_CARD", extracted_value="6222021234567890128"), \
        "FUNCTION 里的银行卡号没识别"


# ── TEST 3: MySQL TRIGGER 被扫到（图片里的第 2 个改进点）──────────
def test_mysql_trigger_covered():
    routes = {
        "information_schema.ROUTINES": [],
        "information_schema.TRIGGERS": [
            {
                "TRIGGER_NAME": "trg_log_insert",
                "ACTION_STATEMENT":
                    "INSERT INTO audit_log (phone) VALUES ('13999998888');",
            },
        ],
        "information_schema.VIEWS": [],
    }
    conn = FakeMySQLConn(routes)
    findings = scan_db_objects(conn, "mysql", "testdb")

    assert assert_finding(findings,
        table_name="__stored_procedure__",  # 触发器也归到 __stored_procedure__
        field_name="trg_log_insert",
        sensitive_type="PHONE_NUMBER", extracted_value="13999998888"), \
        "TRIGGER 里的手机号没识别"


# ── TEST 4: MySQL VIEW 走 SHOW CREATE VIEW 完整定义 ───────────────
def test_mysql_view_show_create():
    """
    模拟 VIEW_DEFINITION 被截断（短），SHOW CREATE VIEW 返回完整。
    应该以 SHOW CREATE VIEW 的内容为准识别敏感信息。
    """
    routes = {
        "information_schema.ROUTINES": [],
        "information_schema.TRIGGERS": [],
        "information_schema.VIEWS": [
            {
                "TABLE_NAME": "v_customer",
                "VIEW_DEFINITION": "SELECT * FROM users -- 截断",  # 不含敏感值
            },
        ],
        "SHOW CREATE VIEW": [
            # SHOW CREATE VIEW 返回 (View, Create View, cset, coll)
            {
                "View": "v_customer",
                "Create View":
                    "CREATE VIEW v_customer AS "
                    "SELECT * FROM users "
                    "WHERE phone = '18511112222'",   # ← 敏感值只在完整定义里
            },
        ],
    }
    conn = FakeMySQLConn(routes)
    findings = scan_db_objects(conn, "mysql", "testdb")

    assert assert_finding(findings,
        table_name="__view__", field_name="v_customer",
        sensitive_type="PHONE_NUMBER", extracted_value="18511112222"), \
        "SHOW CREATE VIEW 的完整定义里的手机号没被识别——说明没用到完整 SQL"


# ── TEST 5: MySQL VIEW 的 SHOW CREATE VIEW 失败时 fallback ────────
def test_mysql_view_fallback():
    def raise_on_show_create(sql, params):
        if "SHOW CREATE VIEW" in sql:
            raise Exception("权限不足")
        return []

    routes = {
        "information_schema.ROUTINES": [],
        "information_schema.TRIGGERS": [],
        "information_schema.VIEWS": [
            {
                "TABLE_NAME": "v_fallback",
                "VIEW_DEFINITION": "SELECT email FROM users WHERE email = 'fallback@test.com'",
            },
        ],
        "SHOW CREATE VIEW": raise_on_show_create,
    }
    conn = FakeMySQLConn(routes)
    findings = scan_db_objects(conn, "mysql", "testdb")

    assert assert_finding(findings,
        table_name="__view__", field_name="v_fallback",
        sensitive_type="EMAIL", extracted_value="fallback@test.com"), \
        "SHOW CREATE VIEW 失败后未从 VIEW_DEFINITION fallback"


# ── TEST 6: 同一对象内同一值去重 ─────────────────────────────────
def test_dedup_within_object():
    routes = {
        "information_schema.ROUTINES": [
            {
                "ROUTINE_NAME": "sp_repeat",
                "ROUTINE_TYPE": "PROCEDURE",
                "ROUTINE_DEFINITION":
                    "SELECT * FROM u WHERE phone = '13812345678' "
                    "UNION SELECT * FROM u WHERE phone = '13812345678'",  # 同号两次
            },
        ],
        "information_schema.TRIGGERS": [],
        "information_schema.VIEWS": [],
    }
    conn = FakeMySQLConn(routes)
    findings = scan_db_objects(conn, "mysql", "testdb")

    n = count_findings(findings,
        field_name="sp_repeat",
        sensitive_type="PHONE_NUMBER", extracted_value="13812345678")
    assert n == 1, f"同一值在同一对象内应该只记录一次，实际 {n} 次"


# ── TEST 7: PostgreSQL 函数 + 视图基础识别 ───────────────────────
def test_pg_functions_and_views():
    routes = {
        "pg_proc": [
            # PG cursor 返回 tuple
            ("sp_sync_data",
             "CREATE FUNCTION sp_sync_data() ... "
             "  SET @conn = 'host=db1 password=MyP@ssw0rd123 user=admin';"),
        ],
        "pg_class": [
            ("v_customer_summary",
             "SELECT id, phone FROM users WHERE phone = '13700137000'"),
        ],
        "pg_trigger": [],
    }
    conn = FakePGConn(routes)
    findings = scan_db_objects(conn, "postgresql", "testdb")

    # 函数里的密码
    assert assert_finding(findings,
        db_type="postgresql", table_name="__stored_procedure__",
        field_name="sp_sync_data",
        sensitive_type="PASSWORD_OR_SECRET"), \
        "PG 函数里的密码未识别"

    # 视图里的手机号
    assert assert_finding(findings,
        db_type="postgresql", table_name="__view__",
        field_name="v_customer_summary",
        sensitive_type="PHONE_NUMBER", extracted_value="13700137000"), \
        "PG 视图里的手机号未识别"


# ── TEST 8: PG 排除 pg_catalog / information_schema ──────────────
def test_pg_excludes_system_schemas():
    """
    模拟：如果扫描 SQL 没排除系统 schema，就会拿到 pg_catalog 的内置函数，
    本测试检查发送的 SQL 是否包含排除条件。
    """
    captured_sqls = []

    class CapturingCursor(FakeCursor):
        def execute(self, sql, params=None):
            captured_sqls.append(sql)
            super().execute(sql, params)

    class CapturingPGConn(FakePGConn):
        def cursor(self, cursor_factory=None):
            return CapturingCursor(self.routes, dict_mode=False)

    conn = CapturingPGConn({"pg_proc": [], "pg_class": [], "pg_trigger": []})
    scan_db_objects(conn, "postgresql", "testdb")

    has_exclusion = any(
        ("NOT IN" in sql and "pg_catalog" in sql) or "nspname NOT LIKE" in sql
        for sql in captured_sqls
    )
    assert has_exclusion, f"PG 查询 SQL 没有排除系统 schema，会扫到内置对象。SQLs: {captured_sqls}"


# ── TEST 9: 错误隔离 ─────────────────────────────────────────────
def test_error_isolation():
    """
    ROUTINES 查询抛异常时，TRIGGERS 和 VIEWS 仍应被扫描。
    """
    def raise_on_routines(sql, params):
        raise Exception("模拟权限错误")

    routes = {
        "information_schema.ROUTINES": raise_on_routines,
        "information_schema.TRIGGERS": [
            {"TRIGGER_NAME": "trg_ok",
             "ACTION_STATEMENT": "CALL log('18666661234')"},
        ],
        "information_schema.VIEWS": [],
    }
    conn = FakeMySQLConn(routes)
    findings = scan_db_objects(conn, "mysql", "testdb")

    assert assert_finding(findings,
        field_name="trg_ok", sensitive_type="PHONE_NUMBER"), \
        "ROUTINES 失败后 TRIGGERS 没继续扫描——错误隔离失效"


# ── TEST 10: record_id 是 em-dash 不是普通连字符 ─────────────────
def test_record_id_is_em_dash():
    routes = {
        "information_schema.ROUTINES": [
            {"ROUTINE_NAME": "p", "ROUTINE_TYPE": "PROCEDURE",
             "ROUTINE_DEFINITION": "SET @x='13800138000'"},
        ],
        "information_schema.TRIGGERS": [],
        "information_schema.VIEWS": [],
    }
    conn = FakeMySQLConn(routes)
    findings = scan_db_objects(conn, "mysql", "testdb")

    assert findings, "没产生任何 finding"
    rid = findings[0]["record_id"]
    assert rid == "\u2014", f"record_id 应为 em-dash (U+2014)，实际是 {rid!r} (U+{ord(rid):04X})"


# ═══════════════════════════════════════════════════════════════
# 主流程
# ═══════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("dbobject.py 本地 mock 测试（不需要 docker）")
    print("=" * 60)

    tests = [
        ("MySQL PROCEDURE 基础识别", test_mysql_procedure_basic),
        ("MySQL FUNCTION 被扫到（图片改进点 1）", test_mysql_function_covered),
        ("MySQL TRIGGER 被扫到（图片改进点 2）", test_mysql_trigger_covered),
        ("MySQL VIEW 用 SHOW CREATE VIEW 拿完整定义", test_mysql_view_show_create),
        ("MySQL VIEW 的 SHOW CREATE VIEW 失败时 fallback", test_mysql_view_fallback),
        ("同一对象内同一敏感值去重", test_dedup_within_object),
        ("PG 函数+视图基础识别", test_pg_functions_and_views),
        ("PG 查询排除 pg_catalog / information_schema", test_pg_excludes_system_schemas),
        ("错误隔离：一类对象失败不影响其他", test_error_isolation),
        ("record_id 是 em-dash (U+2014)", test_record_id_is_em_dash),
    ]

    for name, fn in tests:
        run(name, fn)

    print()
    print("=" * 60)
    print(f"通过: {len(PASSED)} / {len(PASSED) + len(FAILED)}")
    if FAILED:
        print(f"失败: {len(FAILED)}")
        for name, msg in FAILED:
            print(f"  - {name}: {msg}")
        sys.exit(1)
    else:
        print("全部通过 ✨")


if __name__ == "__main__":
    main()
