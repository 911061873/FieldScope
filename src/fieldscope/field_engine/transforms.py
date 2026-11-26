from __future__ import annotations

import hashlib
from typing import Any

# Precedence used when multiple external roles specify conflicting transforms (higher = stricter)
TRANSFORM_STRICTNESS: dict[str, int] = {
    "redact": 100,
    "hash": 80,
    "mask_middle": 60,
    "mask_phone": 50,
    "mask_email": 50,
}


def mask_phone(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    digits_or_str = value.strip()
    if len(digits_or_str) <= 4:
        return "****"
    if len(digits_or_str) <= 7:
        return digits_or_str[:2] + "*" * (len(digits_or_str) - 3) + digits_or_str[-1:]
    return digits_or_str[:3] + "****" + digits_or_str[-4:]


def mask_email(value: Any) -> Any:
    if not isinstance(value, str) or "@" not in value:
        return mask_middle(value)
    local, domain = value.split("@", 1)
    if len(local) <= 1:
        masked_local = "*"
    elif len(local) == 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "***" + local[-1]
    return f"{masked_local}@{domain}"


def mask_middle(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    if len(value) <= 2:
        return "*" * len(value)
    if len(value) <= 4:
        return value[0] + "*" * (len(value) - 2) + value[-1]
    keep = max(1, min(2, len(value) // 4))
    return value[:keep] + "***" + value[-keep:]


def redact_value(_value: Any) -> str:
    return "[REDACTED]"


def hash_value(value: Any) -> Any:
    if value is None:
        return None
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]
    return f"sha256:{digest}"


def apply_transform(action: str, value: Any) -> Any:
    if value is None:
        return None
    if action == "mask_phone":
        return mask_phone(value)
    if action == "mask_email":
        return mask_email(value)
    if action == "mask_middle":
        return mask_middle(value)
    if action == "redact":
        return redact_value(value)
    if action == "hash":
        return hash_value(value)
    return value
