from .config import MAX_SCAN_LEN


def extract_sensitive_from_value(value):
    if not isinstance(value, str):
        return None
    value_str = value
    if len(value_str) > MAX_SCAN_LEN:
        value_str = value_str[:MAX_SCAN_LEN]
    # Further processing...
    return value_str