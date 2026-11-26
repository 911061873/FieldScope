import { resolvePath } from "./expr.ts";

const EXACT_TEMPLATE_REGEX = /^\{\{\s*([a-zA-Z0-9_$.-]+)\s*\}\}$/;
const INLINE_TEMPLATE_REGEX = /\{\{\s*([a-zA-Z0-9_$.-]+)\s*\}\}/g;

/**
 * Resolves `{{ path.to.value }}` templates against the evaluation context.
 * If the entire string is a single template, preserves the resolved value's native type.
 */
export function resolveTemplateValue(
  template: unknown,
  context: Record<string, unknown>
): unknown {
  if (typeof template !== "string") {
    return template;
  }

  const exactMatch = template.match(EXACT_TEMPLATE_REGEX);
  if (exactMatch) {
    return resolvePath(context, exactMatch[1]);
  }

  return template.replace(INLINE_TEMPLATE_REGEX, (_full, path: string) => {
    const val = resolvePath(context, path);
    return val === undefined || val === null ? "" : String(val);
  });
}

export function setNestedValue(
  target: Record<string, unknown>,
  path: string,
  value: unknown
): void {
  const parts = path.split(".");
  let current: Record<string, unknown> = target;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    const next = current[key];
    if (typeof next !== "object" || next === null || Array.isArray(next)) {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }
  const last = parts[parts.length - 1];
  current[last] = value;
}
