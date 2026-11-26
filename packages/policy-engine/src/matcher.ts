import type { HttpMethod, Principal, PrincipalMatch } from "@fieldscope/core";

export function matchPrincipal(
  principal: Principal,
  rule: PrincipalMatch
): boolean {
  if (rule.userIds && rule.userIds.length > 0) {
    if (!rule.userIds.includes(principal.userId)) {
      return false;
    }
  }

  if (rule.roles && rule.roles.length > 0) {
    const hasAnyRole = rule.roles.some((r) => principal.roles.includes(r));
    if (!hasAnyRole) {
      return false;
    }
  }

  if (rule.agentIds && rule.agentIds.length > 0) {
    if (!principal.agentId || !rule.agentIds.includes(principal.agentId)) {
      return false;
    }
  }

  if (rule.attributes) {
    for (const [key, expected] of Object.entries(rule.attributes)) {
      const actual = principal.attributes[key];
      if (Array.isArray(expected)) {
        if (!expected.includes(actual)) return false;
      } else if (actual !== expected) {
        return false;
      }
    }
  }

  return true;
}

export function matchMethod(method: string, allowed: HttpMethod[]): boolean {
  const upper = method.toUpperCase();
  return allowed.some((m) => m === "*" || m.toUpperCase() === upper);
}

/**
 * Matches URL paths against glob-like patterns:
 * - `*` matches any characters except `/`
 * - `**` matches any characters including `/`
 */
export function matchPath(path: string, pattern: string): boolean {
  const normalizedPath = normalizePath(path);
  const normalizedPattern = normalizePath(pattern);

  if (normalizedPattern === "/**" || normalizedPattern === "*") {
    return true;
  }

  const regexStr = normalizedPattern
    .split("**")
    .map((segment) =>
      segment
        .split("*")
        .map((lit) => escapeRegex(lit))
        .join("[^/]*")
    )
    .join(".*");

  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(normalizedPath);
}

function normalizePath(p: string): string {
  const clean = p.split("?")[0] ?? p;
  if (!clean.startsWith("/")) return `/${clean}`;
  return clean;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
