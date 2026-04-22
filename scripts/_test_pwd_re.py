# -*- coding: utf-8 -*-
import sys, io, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.patterns import extract_sensitive_from_value

# Realistic stored procedure bodies (what dbobject.py feeds in)
samples = [
    ("hardcoded FP", """
CREATE OR REPLACE FUNCTION sp_audit_citizens()
RETURNS void AS $$
DECLARE
    v_password VARCHAR(64) := 'hardcoded';
BEGIN
    PERFORM 1;
END;
$$ LANGUAGE plpgsql;
"""),
    ("real password TP", """
CREATE OR REPLACE FUNCTION sp_sync() RETURNS void AS $$
DECLARE
    v_password VARCHAR := 'MySecretPwd2024!';
BEGIN
    PERFORM 1;
END;
$$ LANGUAGE plpgsql;
"""),
    ("sk key TP", "SELECT * FROM api WHERE api_key = 'sk-AbC123dEf456gHi789'"),
]

for name, sql in samples:
    out = [(t, v) for t, v in extract_sensitive_from_value(sql) if t == "PASSWORD_OR_SECRET"]
    print(f"{name}: {out}")
