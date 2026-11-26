from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from fieldscope.field_engine.transforms import apply_transform


@dataclass
class MergedFieldRules:
    """Effective field-level pruning and masking configuration after multi-role merging."""

    mode: str  # "none" | "allowlist" | "denylist"
    fields: list[str] = field(default_factory=list)
    denied_fields: list[str] = field(default_factory=list)
    transforms: dict[str, str] = field(default_factory=dict)  # normalized_path -> action


@dataclass
class FieldProcessingResult:
    data: Any
    pruned_fields: list[str]
    transformed_fields: list[str]


def normalize_field_path(path: str) -> str:
    """Normalize field paths like '$.data.items[*].phone' -> 'data.items[*].phone'."""
    p = path.strip()
    if p.startswith("$."):
        p = p[2:]
    elif p.startswith("$"):
        p = p[1:]
    return p.strip(".")


def _parse_segments(path: str) -> list[str]:
    norm = normalize_field_path(path)
    if not norm:
        return []
    segments: list[str] = []
    for raw_part in norm.split("."):
        if raw_part.endswith("[*]"):
            base = raw_part[:-3]
            if base:
                segments.append(base)
            segments.append("[*]")
        else:
            segments.append(raw_part)
    return segments


def _format_audit_path(prefix: str, key: str) -> str:
    if not prefix:
        return key
    if key == "[*]":
        return f"{prefix}[*]"
    return f"{prefix}.{key}"


def _build_allow_tree(paths: list[str]) -> dict[str, Any]:
    """Build a prefix tree where True means keep the entire subtree."""
    root: dict[str, Any] = {}
    for path in paths:
        segs = _parse_segments(path)
        if not segs:
            continue
        node = root
        for idx, seg in enumerate(segs):
            is_last = idx == len(segs) - 1
            if is_last:
                node[seg] = True
            else:
                existing = node.get(seg)
                if existing is True:
                    # Whole parent subtree is already allowed
                    break
                if not isinstance(existing, dict):
                    existing = {}
                    node[seg] = existing
                node = existing
    return root


def _project_allowlist(
    data: Any,
    tree: dict[str, Any] | bool,
    prefix: str,
    pruned: set[str],
) -> Any:
    if tree is True:
        return copy.deepcopy(data)

    if isinstance(data, list):
        if isinstance(tree, dict) and "[*]" in tree:
            child_tree = tree["[*]"]
            next_prefix = _format_audit_path(prefix, "[*]")
            return [_project_allowlist(item, child_tree, next_prefix, pruned) for item in data]
        return []

    if isinstance(data, dict) and isinstance(tree, dict):
        result: dict[str, Any] = {}
        for key, value in data.items():
            path_str = _format_audit_path(prefix, key)
            if key in tree:
                result[key] = _project_allowlist(value, tree[key], path_str, pruned)
            elif "*" in tree:
                result[key] = _project_allowlist(value, tree["*"], path_str, pruned)
            else:
                pruned.add(path_str)
        return result

    return copy.deepcopy(data)


def _prune_denylist_path(
    data: Any,
    segments: list[str],
    prefix: str,
    pruned: set[str],
) -> None:
    if not segments:
        return
    head, tail = segments[0], segments[1:]

    if head == "[*]":
        if isinstance(data, list):
            next_prefix = _format_audit_path(prefix, "[*]")
            for item in data:
                _prune_denylist_path(item, tail, next_prefix, pruned)
        return

    if isinstance(data, dict):
        keys = list(data.keys()) if head == "*" else ([head] if head in data else [])
        for key in keys:
            path_str = _format_audit_path(prefix, key)
            if not tail:
                del data[key]
                pruned.add(path_str)
            else:
                _prune_denylist_path(data[key], tail, path_str, pruned)


def _apply_transform_path(
    data: Any,
    segments: list[str],
    action: str,
    prefix: str,
    transformed: set[str],
) -> None:
    if not segments:
        return
    head, tail = segments[0], segments[1:]

    if head == "[*]":
        if isinstance(data, list):
            next_prefix = _format_audit_path(prefix, "[*]")
            for item in data:
                _apply_transform_path(item, tail, action, next_prefix, transformed)
        return

    if isinstance(data, dict):
        keys = list(data.keys()) if head == "*" else ([head] if head in data else [])
        for key in keys:
            path_str = _format_audit_path(prefix, key)
            if not tail:
                if data[key] is not None:
                    data[key] = apply_transform(action, data[key])
                    transformed.add(path_str)
            else:
                _apply_transform_path(data[key], tail, action, path_str, transformed)


def apply_field_rules(data: Any, rules: MergedFieldRules) -> FieldProcessingResult:
    """Apply merged allowlist/denylist pruning and field masking transforms to JSON data."""
    pruned: set[str] = set()
    transformed: set[str] = set()

    if rules.mode == "allowlist":
        tree = _build_allow_tree(rules.fields)
        working = _project_allowlist(data, tree, "", pruned)
    else:
        working = copy.deepcopy(data)

    # Apply explicit denylist paths (also enforces explicit-deny over allowlist)
    deny_targets = list(rules.denied_fields)
    if rules.mode == "denylist":
        deny_targets.extend(rules.fields)
    for deny_path in dict.fromkeys(deny_targets):
        segs = _parse_segments(deny_path)
        if segs:
            _prune_denylist_path(working, segs, "", pruned)

    # Apply field masking/redaction transforms
    for path, action in rules.transforms.items():
        segs = _parse_segments(path)
        if segs:
            _apply_transform_path(working, segs, action, "", transformed)

    return FieldProcessingResult(
        data=working,
        pruned_fields=sorted(pruned),
        transformed_fields=sorted(transformed),
    )
