import pymysql
import psycopg2
import psycopg2.extras
from core.config import DB_CONFIGS


def get_connection(db_type: str, db_name: str):
    cfg = DB_CONFIGS.get(db_type)
    if cfg is None:
        print(f"[ERROR] 未知 db_type: {db_type}")
        return None
    try:
        if db_type == "mysql":
            return pymysql.connect(
                host=cfg["host"],
                port=cfg["port"],
                user=cfg["user"],
                password=cfg["password"],
                database=db_name,
                charset="utf8mb4",
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=10,
            )
        elif db_type == "postgresql":
            return psycopg2.connect(
                host=cfg["host"],
                port=cfg["port"],
                user=cfg["user"],
                password=cfg["password"],
                dbname=db_name,
                connect_timeout=10,
            )
    except Exception as e:
        print(f"[ERROR] 连接 {db_type}/{db_name} 失败: {e}")
        return None


def get_all_tables(conn, db_type: str, db_name: str) -> list:
    try:
        if db_type == "mysql":
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT TABLE_NAME FROM information_schema.TABLES "
                    "WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'BASE TABLE'",
                    (db_name,),
                )
                return [row["TABLE_NAME"] for row in cur.fetchall()]
        elif db_type == "postgresql":
            with conn.cursor() as cur:
                cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                return [row[0] for row in cur.fetchall()]
    except Exception as e:
        print(f"[ERROR] 获取表列表失败 {db_type}/{db_name}: {e}")
        return []


def get_primary_key_col(conn, db_type: str, db_name: str, table_name: str):
    try:
        if db_type == "mysql":
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS "
                    "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_KEY = 'PRI'",
                    (db_name, table_name),
                )
                for row in cur.fetchall():
                    if row["DATA_TYPE"] in ("int", "bigint", "smallint", "tinyint", "mediumint"):
                        return row["COLUMN_NAME"]
                return None
        elif db_type == "postgresql":
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT a.attname, t.typname
                    FROM pg_index i
                    JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                    JOIN pg_type t ON t.oid = a.atttypid
                    WHERE i.indrelid = %s::regclass AND i.indisprimary
                    """,
                    (table_name,),
                )
                for col_name, type_name in cur.fetchall():
                    if type_name in ("int4", "int8", "int2", "int", "integer", "bigint",
                                     "smallint", "serial", "bigserial"):
                        return col_name
                return None
    except Exception as e:
        print(f"[ERROR] 获取主键失败 {table_name}: {e}")
        return None


def stream_table_rows(conn, db_type: str, table_name: str, pk_col):
    FETCH_SIZE = 500  # [P3] 从 200 提升到 500，减少网络往返次数
    try:
        if db_type == "mysql":
            with conn.cursor() as cur:
                cur.execute(f"SELECT * FROM `{table_name}`")
                row_num = 0
                while True:
                    rows = cur.fetchmany(FETCH_SIZE)
                    if not rows:
                        break
                    for row in rows:
                        row_num += 1
                        pk_value = row.get(pk_col, row_num) if pk_col else row_num
                        yield (pk_value, dict(row))
        elif db_type == "postgresql":
            # [B6] 用 with 管理 cursor，确保生成器提前关闭（超时 break）时也能释放游标
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f'SELECT * FROM "{table_name}"')
                row_num = 0
                while True:
                    rows = cur.fetchmany(FETCH_SIZE)
                    if not rows:
                        break
                    for row in rows:
                        row_num += 1
                        row_dict = dict(row)
                        pk_value = row_dict.get(pk_col, row_num) if pk_col else row_num
                        yield (pk_value, row_dict)
    except Exception as e:
        print(f"[ERROR] 流式读取 {table_name} 失败: {e}")
