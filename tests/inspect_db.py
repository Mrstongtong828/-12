# tests/inspect_db.py
import pymysql

conn = pymysql.connect(
    host='127.0.0.1', port=3306, user='root', password='rootpass123',
    database='fintech_db', charset='utf8mb4',
    cursorclass=pymysql.cursors.DictCursor,
)

TABLE = 'credit_report'

with conn.cursor() as cur:
    cur.execute(f'DESCRIBE `{TABLE}`')
    print(f'=== {TABLE} 列结构 ===')
    for r in cur.fetchall():
        print(f"  {r['Field']:<28} {r['Type']:<22} {r['Key']}")

    cur.execute(f'SELECT * FROM `{TABLE}` LIMIT 4')
    print(f'\n=== {TABLE} 样本 ===')
    for i, r in enumerate(cur.fetchall()):
        print(f'\n--- 行 {i} ---')
        for k, v in r.items():
            s = str(v) if v is not None else 'NULL'
            if len(s) > 200:
                s = s[:200] + f' ...[truncated, total {len(str(v))} chars]'
            print(f'  {k:<22} = {s}')

conn.close()