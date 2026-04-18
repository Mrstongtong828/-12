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
    """
    优先级链：
      1. 优先找名字匹配 <table>_id 或 {table_name_singular}_id 的整型列
      2. 否则找任何名字以 _id 结尾或等于 id 的整型列
      3. 否则退到真实主键(原逻辑)
      4. 都没有返回 None(调用方会降级为行号)
    """
    try:
        if db_type == "mysql":
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COLUMN_NAME, DATA_TYPE, COLUMN_KEY, ORDINAL_POSITION "
                    "FROM information_schema.COLUMNS "
                    "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s "
                    "ORDER BY ORDINAL_POSITION",
                    (db_name, table_name),
                )
                cols = cur.fetchall()
            return _pick_pk_from_cols(cols, table_name, is_mysql=True)

        elif db_type == "postgresql":
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT a.attname, t.typname, a.attnum
                    FROM pg_attribute a
                    JOIN pg_type t ON t.oid = a.atttypid
                    WHERE a.attrelid = %s::regclass
                      AND a.attnum > 0
                      AND NOT a.attisdropped
                    ORDER BY a.attnum
                    """,
                    (table_name,),
                )
                rows = cur.fetchall()
            # 标准化成 dict 列表，复用下面的选择逻辑
            cols = [{"COLUMN_NAME": r[0], "DATA_TYPE": r[1],
                     "COLUMN_KEY": "", "ORDINAL_POSITION": r[2]}
                    for r in rows]
            # PG 的主键查一次单独补上
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT a.attname FROM pg_index i "
                    "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
                    "WHERE i.indrelid = %s::regclass AND i.indisprimary",
                    (table_name,),
                )
                pk_names = {r[0] for r in cur.fetchall()}
            for c in cols:
                if c["COLUMN_NAME"] in pk_names:
                    c["COLUMN_KEY"] = "PRI"
            return _pick_pk_from_cols(cols, table_name, is_mysql=False)
    except Exception as e:
        print(f"[ERROR] 获取主键失败 {table_name}: {e}")
        return None


_INT_TYPES_MYSQL = {"int", "bigint", "smallint", "tinyint", "mediumint"}
_INT_TYPES_PG = {"int2", "int4", "int8", "int", "integer",
                 "bigint", "smallint", "serial", "bigserial"}


def _pick_pk_from_cols(cols, table_name, is_mysql=True):
    """
    从列元数据里挑最适合当 record_id 的列。
    cols: [{"COLUMN_NAME", "DATA_TYPE", "COLUMN_KEY", "ORDINAL_POSITION"}, ...]
    """
    int_types = _INT_TYPES_MYSQL if is_mysql else _INT_TYPES_PG

    # 只保留整型列
    int_cols = [c for c in cols if c["DATA_TYPE"].lower() in int_types]
    if not int_cols:
        return None

    # 预计算 name -> col 的映射
    lower_name = {c["COLUMN_NAME"].lower(): c for c in int_cols}

    # === 层级 1: 业务主键命名（最优先）===
    # 精确匹配 <table>_id / <singular_table>_id
    tname = table_name.lower()
    candidates = [f"{tname}_id"]
    # 常见表名复数去尾：users -> user_id, orders -> order_id, categories -> category_id
    if tname.endswith("ies") and len(tname) > 3:
        candidates.append(f"{tname[:-3]}y_id")
    elif tname.endswith("s") and len(tname) > 1:
        candidates.append(f"{tname[:-1]}_id")
    for cand in candidates:
        if cand in lower_name:
            return lower_name[cand]["COLUMN_NAME"]

    # === 层级 2: 名字匹配 id 或 *_id（次优先）===
    # 先找 "id"
    if "id" in lower_name:
        return lower_name["id"]["COLUMN_NAME"]
    # 再找任何 _id 结尾的
    for lname, c in lower_name.items():
        if lname.endswith("_id"):
            return c["COLUMN_NAME"]

    # === 层级 3: 真实主键（最后兜底）===
    for c in int_cols:
        if c["COLUMN_KEY"] == "PRI":
            return c["COLUMN_NAME"]

    # === 层级 4: 第一个整型列 ===
    return int_cols[0]["COLUMN_NAME"]

 


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
