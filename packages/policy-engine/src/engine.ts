import type { Policy, Principal, ResponseRule } from "@fieldscope/core";
import { evaluateExpression } from "./expr.ts";
import {
  matchMethod,
  matchPath,
  matchPrincipal,
  matchToolName,
} from "./matcher.ts";
import { resolveTemplateValue, setNestedValue } from "./template.ts";

export interface PolicyEvaluationInput {
  principal: Principal;
  connectorId: string;
  protocol?: "http" | "mcp";
  method: string;
  path: string;
  toolName?: string;
  query?: Record<string, unknown>;
  body?: unknown;
  args?: Record<string, unknown>;
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  matchedPolicyId?: string;
  reason?: string;
  query: Record<string, unknown>;
  body: unknown;
  args: Record<string, unknown>;
  enforcedParams: string[];
  responseRule?: ResponseRule;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function policyMatchesTarget(
  policy: Policy,
  input: {
    principal: Principal;
    connectorId: string;
    protocol: "http" | "mcp";
    method: string;
    path: string;
    toolName?: string;
  }
): boolean {
  if (
    policy.match.connector !== "*" &&
    policy.match.connector !== input.connectorId
  ) {
    return false;
  }
  if (policy.action.protocol !== input.protocol) {
    return false;
  }
  if (!matchPrincipal(input.principal, policy.match.principal)) {
    return false;
  }

  if (input.protocol === "mcp") {
    const toolName = input.toolName ?? "";
    const patterns =
      policy.action.tools && policy.action.tools.length > 0
        ? policy.action.tools
        : ["*"];
    return patterns.some((pattern) => matchToolName(toolName, pattern));
  }

  if (!matchMethod(input.method, policy.action.methods)) {
    return false;
  }
  return policy.action.paths.some((pattern) => matchPath(input.path, pattern));
}

/**
 * Checks whether an MCP tool should be exposed to the given principal during `tools/list`.
 * Applies Default Deny + Explicit Deny overrides Allow.
 */
export function isToolVisible(
  policies: Policy[],
  principal: Principal,
  connectorId: string,
  toolName: string
): boolean {
  const matching = policies.filter((p) =>
    policyMatchesTarget(p, {
      principal,
      connectorId,
      protocol: "mcp",
      method: "POST",
      path: "/mcp",
      toolName,
    })
  );
  if (matching.length === 0) return false;
  if (matching.some((p) => p.effect === "deny")) return false;
  return matching.some((p) => p.effect === "allow");
}

/**
 * Evaluates a set of policies against an incoming HTTP or MCP request.
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
  const argsCopy: Record<string, unknown> = structuredClone(input.args ?? {});

  const matching = policies.filter((policy) =>
    policyMatchesTarget(policy, {
      principal: input.principal,
      connectorId: input.connectorId,
      protocol,
      method: input.method,
      path: input.path,
      toolName: input.toolName,
    })
  );

  if (matching.length === 0) {
    const targetDesc =
      protocol === "mcp"
        ? `MCP tool '${input.toolName ?? ""}'`
        : `${input.method.toUpperCase()} ${input.path}`;
    return {
      allowed: false,
      reason: `Access denied: no policy allows ${targetDesc} on connector '${input.connectorId}'`,
      query: queryCopy,
      body: bodyCopy,
      args: argsCopy,
      enforcedParams: [],
    };
  }

  const sorted = [...matching].sort((a, b) => b.priority - a.priority);

  const denyPolicy = sorted.find((p) => p.effect === "deny");
  if (denyPolicy) {
    return {
      allowed: false,
      matchedPolicyId: denyPolicy.id,
      reason: `Access denied by explicit deny policy '${denyPolicy.name ?? denyPolicy.id}'`,
      query: queryCopy,
      body: bodyCopy,
      args: argsCopy,
      enforcedParams: [],
    };
  }

  const allowPolicy = sorted[0];
  const evalContext: Record<string, unknown> = {
    principal: input.principal,
    query: queryCopy,
    body: bodyCopy ?? {},
    args: argsCopy,
    method: input.method.toUpperCase(),
    path: input.path,
    toolName: input.toolName,
  };

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
          args: argsCopy,
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
          args: argsCopy,
          enforcedParams: [],
        };
      }
    }
  }

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
          args: argsCopy,
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
      } else if (targetPath.startsWith("args.")) {
        const nestedPath = targetPath.slice("args.".length);
        setNestedValue(argsCopy, nestedPath, resolved);
        enforcedParams.push(targetPath);
      }
    }
  }

  return {
    allowed: true,
    matchedPolicyId: allowPolicy.id,
    query: queryCopy,
    body: bodyCopy,
    args: argsCopy,
    enforcedParams,
    responseRule: allowPolicy.response,
  };
}
