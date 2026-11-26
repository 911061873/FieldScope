import type { Policy, Principal, ResponseRule } from "@fieldscope/core";
import { evaluateExpression } from "./expr.ts";
import { matchMethod, matchPath, matchPrincipal } from "./matcher.ts";
import { resolveTemplateValue, setNestedValue } from "./template.ts";

export interface PolicyEvaluationInput {
  principal: Principal;
  connectorId: string;
  protocol?: "http" | "mcp";
  method: string;
  path: string;
  query?: Record<string, unknown>;
  body?: unknown;
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  matchedPolicyId?: string;
  reason?: string;
  query: Record<string, unknown>;
  body: unknown;
  enforcedParams: string[];
  responseRule?: ResponseRule;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Evaluates a set of policies against an incoming request.
 * Security model:
 * - Default Deny when no policy matches.
 * - Explicit Deny overrides Allow.
 * - Highest priority Allow policy governs request validation, parameter enforcement, and response rules.
 */
export function evaluatePolicies(
  policies: Policy[],
  input: PolicyEvaluationInput
): PolicyEvaluationResult {
  const protocol = input.protocol ?? "http";
  const queryCopy: Record<string, unknown> = structuredClone(input.query ?? {});
  let bodyCopy: unknown =
    input.body === undefined ? undefined : structuredClone(input.body);

  const matching = policies.filter((policy) => {
    if (policy.match.connector !== "*" && policy.match.connector !== input.connectorId) {
      return false;
    }
    if (policy.action.protocol !== protocol) {
      return false;
    }
    if (!matchPrincipal(input.principal, policy.match.principal)) {
      return false;
    }
    if (!matchMethod(input.method, policy.action.methods)) {
      return false;
    }
    const pathMatches = policy.action.paths.some((pattern) =>
      matchPath(input.path, pattern)
    );
    return pathMatches;
  });

  if (matching.length === 0) {
    return {
      allowed: false,
      reason: `Access denied: no policy allows ${input.method.toUpperCase()} ${input.path} on connector '${input.connectorId}'`,
      query: queryCopy,
      body: bodyCopy,
      enforcedParams: [],
    };
  }

  // Sort by priority descending (higher number wins)
  const sorted = [...matching].sort((a, b) => b.priority - a.priority);

  // Explicit deny always overrides allow
  const denyPolicy = sorted.find((p) => p.effect === "deny");
  if (denyPolicy) {
    return {
      allowed: false,
      matchedPolicyId: denyPolicy.id,
      reason: `Access denied by explicit deny policy '${denyPolicy.name ?? denyPolicy.id}'`,
      query: queryCopy,
      body: bodyCopy,
      enforcedParams: [],
    };
  }

  const allowPolicy = sorted[0];
  const evalContext: Record<string, unknown> = {
    principal: input.principal,
    query: queryCopy,
    body: bodyCopy ?? {},
    method: input.method.toUpperCase(),
    path: input.path,
  };

  // 1. Parameter validation rules
  if (allowPolicy.request?.validate) {
    for (const rule of allowPolicy.request.validate) {
      let passed = false;
      try {
        passed = evaluateExpression(rule.expr, evalContext);
      } catch (err) {
        return {
          allowed: false,
          matchedPolicyId: allowPolicy.id,
          reason: `Policy validation expression error (${rule.expr}): ${
            err instanceof Error ? err.message : String(err)
          }`,
          query: queryCopy,
          body: bodyCopy,
          enforcedParams: [],
        };
      }
      if (!passed) {
        return {
          allowed: false,
          matchedPolicyId: allowPolicy.id,
          reason: rule.message,
          query: queryCopy,
          body: bodyCopy,
          enforcedParams: [],
        };
      }
    }
  }

  // 2. Parameter enforcement (force-inject / override query or body parameters)
  const enforcedParams: string[] = [];
  if (allowPolicy.request?.enforce) {
    for (const [targetPath, rawTemplate] of Object.entries(
      allowPolicy.request.enforce
    )) {
      const resolved = resolveTemplateValue(rawTemplate, evalContext);
      if (resolved === undefined) {
        return {
          allowed: false,
          matchedPolicyId: allowPolicy.id,
          reason: `Failed to enforce parameter '${targetPath}': required principal attribute is missing`,
          query: queryCopy,
          body: bodyCopy,
          enforcedParams,
        };
      }

      if (targetPath.startsWith("query.")) {
        const key = targetPath.slice("query.".length);
        queryCopy[key] = resolved;
        enforcedParams.push(targetPath);
      } else if (targetPath.startsWith("body.")) {
        const nestedPath = targetPath.slice("body.".length);
        if (!isPlainObject(bodyCopy)) {
          bodyCopy = {};
        }
        setNestedValue(bodyCopy as Record<string, unknown>, nestedPath, resolved);
        enforcedParams.push(targetPath);
      }
    }
  }

  return {
    allowed: true,
    matchedPolicyId: allowPolicy.id,
    query: queryCopy,
    body: bodyCopy,
    enforcedParams,
    responseRule: allowPolicy.response,
  };
}
