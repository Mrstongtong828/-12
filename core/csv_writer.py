import csv
import re
from core.config import OUTPUT_CSV

COLUMNS = [
    "db_type", "db_name", "table_name", "field_name", "record_id",
    "data_form", "sensitive_type", "sensitive_level", "extracted_value",
]

EM_DASH = "\u2014"

_PLACEHOLDER_RE = re.compile(r"^\[.+\]$")
_NA_NUM_RE = re.compile(r"^N/A_\d+$")
_SKIP_VALUES = {"", "none", "null", "n/a", "nan"}


def _should_skip(value) -> bool:
    if value is None:
        return True
    s = str(value).strip()
    if not s:
        return True
    if s.lower() in _SKIP_VALUES:
        return True
    if _NA_NUM_RE.match(s):
        return True
    if _PLACEHOLDER_RE.match(s):
        return True
    return False


class CSVWriter:
    def __init__(self, filepath: str = OUTPUT_CSV):
        self._file = open(filepath, "w", encoding="utf-8", newline="\n")
        self._writer = csv.DictWriter(
            self._file,
            fieldnames=COLUMNS,
            extrasaction="ignore",
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",
        )
        self._writer.writeheader()
        self._seen: set = set()

    def write_row(self, row_dict: dict) -> bool:
        extracted = row_dict.get("extracted_value")
        if _should_skip(extracted):
            return False
        extracted_stripped = str(extracted).strip()
        # 去重键:完全基于数据位置 + 类型 + 值
        # 同一 (位置, 类型, 值) 只记录一次
        key = (
            str(row_dict.get("db_type", "")),
            str(row_dict.get("db_name", "")),
            str(row_dict.get("table_name", "")),
            str(row_dict.get("field_name", "")),
            str(row_dict.get("record_id", "")),
            str(row_dict.get("sensitive_type", "")),
            extracted_stripped,
        )
        if key in self._seen:
            return False
        self._seen.add(key)
        row = dict(row_dict)
        row["extracted_value"] = extracted_stripped
        self._writer.writerow(row)
        # [防丢] 每写一行立即 flush,防止进程崩溃时丢最后一批行
        # 性能影响:极小(行数通常 <10 万,单次 flush 在 ms 级)
        self._file.flush()
        return True

    def write_multiple_findings(self, base_row: dict, findings_list: list):
        for sensitive_type, sensitive_level, extracted_value in findings_list:
            row = dict(base_row)
            row["sensitive_type"] = sensitive_type
            row["sensitive_level"] = sensitive_level
            row["extracted_value"] = extracted_value
            self.write_row(row)

    def close(self):
        try:
            self._file.flush()
        except Exception:
            pass
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
