from __future__ import annotations

import ast
import re
from typing import Any


class UnsafeExpressionError(ValueError):
    """Raised when a policy expression contains disallowed syntax or unsafe operations."""


_TOKEN_RE = re.compile(
    r"""
    (?P<string>'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")
    |(?P<and>&&)
    |(?P<or>\|\|)
    |(?P<not>!(?!=))
    |(?P<null>\bnull\b)
    |(?P<true>\btrue\b)
    |(?P<false>\bfalse\b)
    """,
    re.VERBOSE,
)


def _normalize_expression(expr: str) -> str:
    """Allow both Pythonic (and/or/not/None) and JS-like (&&/||/!/null/true/false) syntax."""

    def _replace(match: re.Match[str]) -> str:
        if match.group("string") is not None:
            return match.group("string")
        if match.group("and") is not None:
            return " and "
        if match.group("or") is not None:
            return " or "
        if match.group("not") is not None:
            return " not "
        if match.group("null") is not None:
            return "None"
        if match.group("true") is not None:
            return "True"
        if match.group("false") is not None:
            return "False"
        return match.group(0)

    return _TOKEN_RE.sub(_replace, expr)


def _safe_get(target: Any, key: Any) -> Any:
    if target is None:
        return None
    if isinstance(target, dict):
        return target.get(key)
    if isinstance(target, (list, tuple)) and isinstance(key, int):
        if -len(target) <= key < len(target):
            return target[key]
        return None
    if isinstance(key, str) and not key.startswith("_"):
        return getattr(target, key, None)
    return None


def _eval_node(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, context)

    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, int, float, bool, type(None))):
            return node.value
        raise UnsafeExpressionError(f"Unsupported constant type: {type(node.value).__name__}")

    if isinstance(node, ast.Name):
        if node.id.startswith("_"):
            raise UnsafeExpressionError(f"Disallowed identifier: {node.id}")
        return context.get(node.id)

    if isinstance(node, ast.Attribute):
        if node.attr.startswith("_"):
            raise UnsafeExpressionError(f"Disallowed attribute access: {node.attr}")
        base = _eval_node(node.value, context)
        return _safe_get(base, node.attr)

    if isinstance(node, ast.Subscript):
        base = _eval_node(node.value, context)
        index = _eval_node(node.slice, context)
        return _safe_get(base, index)

    if isinstance(node, ast.List):
        return [_eval_node(elt, context) for elt in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_eval_node(elt, context) for elt in node.elts)
    if isinstance(node, ast.Set):
        return {_eval_node(elt, context) for elt in node.elts}

    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            result: Any = True
            for val in node.values:
                result = _eval_node(val, context)
                if not result:
                    return result
            return result
        if isinstance(node.op, ast.Or):
            result = False
            for val in node.values:
                result = _eval_node(val, context)
                if result:
                    return result
            return result
        raise UnsafeExpressionError(f"Unsupported boolean op: {type(node.op).__name__}")

    if isinstance(node, ast.UnaryOp):
        operand = _eval_node(node.operand, context)
        if isinstance(node.op, ast.Not):
            return not bool(operand)
        if isinstance(node.op, ast.USub):
            return -operand if isinstance(operand, (int, float)) else None
        if isinstance(node.op, ast.UAdd):
            return +operand if isinstance(operand, (int, float)) else None
        raise UnsafeExpressionError(f"Unsupported unary op: {type(node.op).__name__}")

    if isinstance(node, ast.BinOp):
        left = _eval_node(node.left, context)
        right = _eval_node(node.right, context)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            return left / right if right != 0 else None
        if isinstance(node.op, ast.Mod):
            return left % right if right != 0 else None
        raise UnsafeExpressionError(f"Unsupported binary op: {type(node.op).__name__}")

    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, context)
        for op, comparator in zip(node.ops, node.comparators, strict=True):
            right = _eval_node(comparator, context)
            if not _apply_compare(op, left, right):
                return False
            left = right
        return True

    raise UnsafeExpressionError(f"Disallowed expression construct: {type(node).__name__}")


def _coerce_numeric_pair(left: Any, right: Any) -> tuple[Any, Any]:
    """Allow comparing numeric query strings like '25' <= 50 cleanly."""
    if isinstance(left, str) and isinstance(right, (int, float)) and not isinstance(right, bool):
        try:
            return float(left), float(right)
        except ValueError:
            return left, right
    if isinstance(right, str) and isinstance(left, (int, float)) and not isinstance(left, bool):
        try:
            return float(left), float(right)
        except ValueError:
            return left, right
    return left, right


def _apply_compare(op: ast.cmpop, left: Any, right: Any) -> bool:
    if isinstance(op, ast.Eq):
        if left is None or right is None:
            return left is right
        l_val, r_val = _coerce_numeric_pair(left, right)
        return bool(l_val == r_val)
    if isinstance(op, ast.NotEq):
        if left is None or right is None:
            return left is not right
        l_val, r_val = _coerce_numeric_pair(left, right)
        return bool(l_val != r_val)
    if isinstance(op, ast.Is):
        return left is right
    if isinstance(op, ast.IsNot):
        return left is not right
    if isinstance(op, ast.In):
        if right is None:
            return False
        try:
            return left in right
        except TypeError:
            return False
    if isinstance(op, ast.NotIn):
        if right is None:
            return True
        try:
            return left not in right
        except TypeError:
            return True

    if left is None or right is None:
        return False
    l_val, r_val = _coerce_numeric_pair(left, right)
    try:
        if isinstance(op, ast.Lt):
            return bool(l_val < r_val)
        if isinstance(op, ast.LtE):
            return bool(l_val <= r_val)
        if isinstance(op, ast.Gt):
            return bool(l_val > r_val)
        if isinstance(op, ast.GtE):
            return bool(l_val >= r_val)
    except TypeError:
        return False

    raise UnsafeExpressionError(f"Unsupported comparison operator: {type(op).__name__}")


def validate_expression_syntax(expr: str) -> None:
    """Validate that an expression parses safely using only whitelisted AST constructs."""
    normalized = _normalize_expression(expr)
    try:
        tree = ast.parse(normalized, mode="eval")
    except SyntaxError as exc:
        raise UnsafeExpressionError(f"Invalid expression syntax: {exc}") from exc

    allowed_nodes = (
        ast.Expression,
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.UnaryOp,
        ast.Not,
        ast.USub,
        ast.UAdd,
        ast.BinOp,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Mod,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.In,
        ast.NotIn,
        ast.Is,
        ast.IsNot,
        ast.Constant,
        ast.Name,
        ast.Load,
        ast.Attribute,
        ast.Subscript,
        ast.List,
        ast.Tuple,
        ast.Set,
    )
    for node in ast.walk(tree):
        if not isinstance(node, allowed_nodes):
            raise UnsafeExpressionError(f"Disallowed AST node: {type(node).__name__}")
        if isinstance(node, ast.Name) and node.id.startswith("_"):
            raise UnsafeExpressionError(f"Disallowed identifier: {node.id}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise UnsafeExpressionError(f"Disallowed attribute: {node.attr}")


def evaluate_expr(expr: str, context: dict[str, Any]) -> Any:
    """Safely evaluate a policy expression against a read-only dictionary context."""
    validate_expression_syntax(expr)
    normalized = _normalize_expression(expr)
    tree = ast.parse(normalized, mode="eval")
    return _eval_node(tree, context)
