from __future__ import annotations

import re
from typing import Any

_SEGMENT_RE = re.compile(
    r"""
    (?:\.?([a-zA-Z0-9_\-$@]+))     # dot or bare identifier
    |(?:\[(\d+)\])                 # array index [0]
    |(?:\['([^']+)'\])             # single-quoted key ['foo.bar']
    |(?:\["([^"]+)"\])             # double-quoted key ["foo.bar"]
    """,
    re.VERBOSE,
)

_MISSING = object()


def parse_json_path(path: str) -> list[str | int]:
    """Parse simple JSONPath expressions like '$.data.items[0].access_token' or 'errcode'."""
    expr = path.strip()
    if expr.startswith("$."):
        expr = expr[2:]
    elif expr == "$":
        return []
    elif expr.startswith("$"):
        expr = expr[1:]

    if not expr:
        return []

    tokens: list[str | int] = []
    pos = 0
    while pos < len(expr):
        match = _SEGMENT_RE.match(expr, pos)
        if not match:
            raise ValueError(f"Unsupported JSONPath syntax near '{expr[pos:]}' in '{path}'")
        ident, idx, sq_key, dq_key = match.groups()
        if ident is not None:
            tokens.append(ident)
        elif idx is not None:
            tokens.append(int(idx))
        elif sq_key is not None:
            tokens.append(sq_key)
        elif dq_key is not None:
            tokens.append(dq_key)
        pos = match.end()
    return tokens


def extract_json_path(data: Any, path: str, default: Any = None) -> Any:
    """Extract a value from nested dict/list using a JSONPath expression."""
    current = data
    for token in parse_json_path(path):
        if isinstance(token, int):
            if isinstance(current, list) and 0 <= token < len(current):
                current = current[token]
            else:
                return default
        else:
            if isinstance(current, dict) and token in current:
                current = current[token]
            else:
                return default
    return current


def extract_json_path_strict(data: Any, path: str) -> tuple[bool, Any]:
    """Extract a value returning (found, value) to distinguish missing from explicit None."""
    result = extract_json_path(data, path, default=_MISSING)
    if result is _MISSING:
        return False, None
    return True, result
