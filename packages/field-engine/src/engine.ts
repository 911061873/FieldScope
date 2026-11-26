import type { FieldTransformRule, ResponseRule } from "@fieldscope/core";
import {
  buildPathTrie,
  parseFieldPath,
  type PathSegment,
  type PathTrieNode,
} from "./path.ts";
import { applyTransformValue } from "./transforms.ts";

export interface FieldEngineResult<T = unknown> {
  data: T;
  prunedFields: string[];
  transformedFields: string[];
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function cloneDeep<T>(value: T): T {
  return structuredClone(value);
}

function formatChildPath(parent: string, key: string): string {
  return parent ? `${parent}.${key}` : key;
}

function formatArrayPath(parent: string): string {
  return `${parent}[*]`;
}

function applyAllowlist(
  value: unknown,
  nodes: PathTrieNode[],
  currentPath: string,
  pruned: Set<string>
): unknown {
  // If any active trie node is terminal, keep the entire subtree intact.
  if (nodes.some((n) => n.terminal)) {
    return cloneDeep(value);
  }

  if (Array.isArray(value)) {
    const nextNodes: PathTrieNode[] = [];
    for (const n of nodes) {
      if (n.wildcardArray) nextNodes.push(n.wildcardArray);
    }
    if (nextNodes.length === 0) {
      if (currentPath) pruned.add(currentPath);
      return [];
    }
    const arrayPath = formatArrayPath(currentPath);
    return value.map((item) => applyAllowlist(item, nextNodes, arrayPath, pruned));
  }

  if (isPlainObject(value)) {
    const result: Record<string, unknown> = {};
    for (const [key, childVal] of Object.entries(value)) {
      const childPath = formatChildPath(currentPath, key);
      const nextNodes: PathTrieNode[] = [];
      for (const n of nodes) {
        const exact = n.keys.get(key);
        if (exact) nextNodes.push(exact);
        if (n.wildcardKey) nextNodes.push(n.wildcardKey);
      }
      if (nextNodes.length === 0) {
        pruned.add(childPath);
        continue;
      }
      result[key] = applyAllowlist(childVal, nextNodes, childPath, pruned);
    }
    return result;
  }

  return value;
}

function applyDenylist(
  value: unknown,
  nodes: PathTrieNode[],
  currentPath: string,
  pruned: Set<string>
): unknown {
  if (nodes.length === 0) {
    return cloneDeep(value);
  }

  if (Array.isArray(value)) {
    const nextNodes: PathTrieNode[] = [];
    for (const n of nodes) {
      if (n.wildcardArray) nextNodes.push(n.wildcardArray);
    }
    if (nextNodes.length === 0) {
      return cloneDeep(value);
    }
    const arrayPath = formatArrayPath(currentPath);
    return value.map((item) => applyDenylist(item, nextNodes, arrayPath, pruned));
  }

  if (isPlainObject(value)) {
    const result: Record<string, unknown> = {};
    for (const [key, childVal] of Object.entries(value)) {
      const childPath = formatChildPath(currentPath, key);
      const nextNodes: PathTrieNode[] = [];
      for (const n of nodes) {
        const exact = n.keys.get(key);
        if (exact) nextNodes.push(exact);
        if (n.wildcardKey) nextNodes.push(n.wildcardKey);
      }
      if (nextNodes.some((n) => n.terminal)) {
        pruned.add(childPath);
        continue;
      }
      result[key] = applyDenylist(childVal, nextNodes, childPath, pruned);
    }
    return result;
  }

  return value;
}

function applyTransformAtSegments(
  value: unknown,
  segments: PathSegment[],
  index: number,
  rule: FieldTransformRule,
  transformed: Set<string>
): unknown {
  if (index === segments.length) {
    transformed.add(rule.path);
    return applyTransformValue(value, rule.action);
  }

  const seg = segments[index];

  if (seg.type === "wildcard_array") {
    if (!Array.isArray(value)) return value;
    return value.map((item) =>
      applyTransformAtSegments(item, segments, index + 1, rule, transformed)
    );
  }

  if (!isPlainObject(value)) return value;

  if (seg.type === "wildcard_key") {
    const next: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      next[k] = applyTransformAtSegments(v, segments, index + 1, rule, transformed);
    }
    return next;
  }

  if (!(seg.key in value)) {
    return value;
  }

  return {
    ...value,
    [seg.key]: applyTransformAtSegments(
      value[seg.key],
      segments,
      index + 1,
      rule,
      transformed
    ),
  };
}

/**
 * Applies FieldScope response governance rules (allowlist/denylist pruning + masking/redaction)
 * without mutating the original payload.
 */
export function applyFieldRules<T = unknown>(
  payload: T,
  rule?: ResponseRule
): FieldEngineResult<T> {
  if (!rule) {
    return {
      data: cloneDeep(payload),
      prunedFields: [],
      transformedFields: [],
    };
  }

  const pruned = new Set<string>();
  const transformed = new Set<string>();

  let current: unknown;
  if (rule.fields.length > 0) {
    const trie = buildPathTrie(rule.fields);
    if (rule.mode === "allowlist") {
      current = applyAllowlist(payload, [trie], "", pruned);
    } else {
      current = applyDenylist(payload, [trie], "", pruned);
    }
  } else if (rule.mode === "allowlist") {
    // Empty allowlist on an object/array means nothing is exposed.
    if (isPlainObject(payload)) {
      for (const key of Object.keys(payload)) pruned.add(key);
      current = {};
    } else if (Array.isArray(payload)) {
      current = [];
    } else {
      current = payload;
    }
  } else {
    current = cloneDeep(payload);
  }

  for (const transformRule of rule.transforms) {
    const segments = parseFieldPath(transformRule.path);
    if (segments.length === 0) continue;
    current = applyTransformAtSegments(
      current,
      segments,
      0,
      transformRule,
      transformed
    );
  }

  return {
    data: current as T,
    prunedFields: Array.from(pruned),
    transformedFields: Array.from(transformed),
  };
}
