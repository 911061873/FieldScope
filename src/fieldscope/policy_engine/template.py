from __future__ import annotations

import re
from typing import Any

_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")


def _lookup_path(context: dict[str, Any], path: str) -> Any:
    current: Any = context
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def render_policy_value(value: Any, context: dict[str, Any]) -> Any:
    """Render {{ user.* }} placeholders inside enforced request parameter values."""
    if isinstance(value, str):
        stripped = value.strip()
        full = _VAR_RE.fullmatch(stripped)
        if full and stripped == value:
            return _lookup_path(context, full.group(1))

        def _repl(match: re.Match[str]) -> str:
            resolved = _lookup_path(context, match.group(1))
            return "" if resolved is None else str(resolved)

        return _VAR_RE.sub(_repl, value)

    if isinstance(value, dict):
        return {k: render_policy_value(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [render_policy_value(item, context) for item in value]
    return value
