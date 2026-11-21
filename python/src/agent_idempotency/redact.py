"""Redact secret-shaped object keys before a snapshot is stored."""

import re
from typing import Any

_SECRET = re.compile(
    r"(password|secret|token|authorization|api[_-]?key|credential|set-cookie)",
    re.IGNORECASE,
)


def redact(value: Any) -> Any:
    """Return a copy with secret-keyed values replaced by `***`."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if isinstance(key, str) and _SECRET.search(key):
                cleaned[key] = "***"
            else:
                cleaned[key] = redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value
