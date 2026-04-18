from core.patterns import extract_sensitive_from_value
from core.config import SENSITIVE_LEVEL_MAP

EM_DASH = "\u2014"


def _make_finding(db_type, db_name, obj_name, obj_kind, sensitive_type, extracted_value):
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
    findings = []
    if not sql_text:
        return findings
    for stype, val in extract_sensitive_from_value(sql_text):
        findings.append(_make_finding(db_type, db_name, obj_name, obj_kind, stype, val))
    return findings


def scan_db_objects(conn, db_type: str, db_name: str):
    findings = []

    if db_type == "mysql":
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT ROUTINE_NAME, ROUTINE_DEFINITION "
                    "FROM information_schema.ROUTINES "
                    "WHERE ROUTINE_SCHEMA = %s AND ROUTINE_TYPE = 'PROCEDURE'",
                    (db_name,),
                )
                for row in cur.fetchall():
                    name = row.get("ROUTINE_NAME") or row[0]
                    defn = row.get("ROUTINE_DEFINITION") or row[1]
                    findings.extend(_scan_sql_text(name, defn, "procedure", db_type, db_name))
        except Exception as e:
            print(f"[ERROR] 扫描MySQL存储过程失败 {db_name}: {e}")

        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT TABLE_NAME, VIEW_DEFINITION "
                    "FROM information_schema.VIEWS "
                    "WHERE TABLE_SCHEMA = %s",
                    (db_name,),
                )
                for row in cur.fetchall():
                    name = row.get("TABLE_NAME") or row[0]
                    defn = row.get("VIEW_DEFINITION") or row[1]
                    findings.extend(_scan_sql_text(name, defn, "view", db_type, db_name))
        except Exception as e:
            print(f"[ERROR] 扫描MySQL视图失败 {db_name}: {e}")

    elif db_type == "postgresql":
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT p.proname, pg_get_functiondef(p.oid) "
                    "FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'public'"
                )
                for row in cur.fetchall():
                    name, defn = row[0], row[1]
                    findings.extend(_scan_sql_text(name, defn, "procedure", db_type, db_name))
        except Exception as e:
            print(f"[ERROR] 扫描PostgreSQL函数失败 {db_name}: {e}")

        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT table_name, pg_get_viewdef(table_name::regclass) "
                    "FROM information_schema.views "
                    "WHERE table_schema = 'public'"
                )
                for row in cur.fetchall():
                    name, defn = row[0], row[1]
                    findings.extend(_scan_sql_text(name, defn, "view", db_type, db_name))
        except Exception as e:
            print(f"[ERROR] 扫描PostgreSQL视图失败 {db_name}: {e}")

    return findings
