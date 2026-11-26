import { randomUUID } from "node:crypto";
import type {
  AuditEvent,
  Connector,
  McpToolMapping,
  Policy,
  Principal,
} from "@fieldscope/core";
import { applyFieldRules } from "@fieldscope/field-engine";
import { evaluatePolicies, isToolVisible } from "@fieldscope/policy-engine";
import {
  injectUpstreamCredential,
  type OAuthTokenManager,
} from "@fieldscope/vault";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface McpToolDescriptor {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface McpHandlerOptions {
  connectors: Connector[];
  policies: Policy[];
  tokenManager?: OAuthTokenManager;
  onAudit?: (event: AuditEvent) => void;
  fetchImpl?: typeof fetch;
  serverInfo?: { name: string; version: string };
}

interface RegisteredRestTool {
  kind: "rest";
  connector: Connector;
  mapping: McpToolMapping;
}

function buildRestToolRegistry(
  connectors: Connector[]
): Map<string, RegisteredRestTool> {
  const map = new Map<string, RegisteredRestTool>();
  for (const connector of connectors) {
    if (!connector.mcpTools) continue;
    for (const mapping of connector.mcpTools) {
      map.set(mapping.name, { kind: "rest", connector, mapping });
    }
  }
  return map;
}

async function fetchUpstreamMcpTools(
  connector: Connector,
  principal: Principal,
  tokenManager: OAuthTokenManager | undefined,
  fetchImpl: typeof fetch
): Promise<McpToolDescriptor[]> {
  const url = new URL(connector.baseUrl);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json",
  };
  await injectUpstreamCredential(connector, principal, url, headers, tokenManager);

  const res = await fetchImpl(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: randomUUID(),
      method: "tools/list",
      params: {},
    }),
    signal: AbortSignal.timeout(connector.timeoutMs),
  });

  if (!res.ok) return [];
  const json = (await res.json()) as {
    result?: { tools?: McpToolDescriptor[] };
  };
  return json.result?.tools ?? [];
}

/**
 * Handles a single MCP JSON-RPC 2.0 request on behalf of an authenticated Principal.
 * Supports:
 * - initialize / ping / notifications/initialized
 * - tools/list (filtered by Principal's MCP policies)
 * - tools/call (policy validation + parameter enforcement + hybrid credential injection + FieldScope pruning/masking)
 */
export async function handleMcpRequest(
  rpc: JsonRpcRequest,
  principal: Principal,
  options: McpHandlerOptions
): Promise<JsonRpcResponse | null> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const restRegistry = buildRestToolRegistry(options.connectors);
  const mcpConnectors = options.connectors.filter((c) => c.protocol === "mcp");
  const id = rpc.id ?? null;

  // Notifications without an id do not expect a response payload
  if (rpc.method === "notifications/initialized") {
    return null;
  }

  if (rpc.method === "ping") {
    return { jsonrpc: "2.0", id, result: {} };
  }

  if (rpc.method === "initialize") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2025-03-26",
        capabilities: {
          tools: { listChanged: false },
        },
        serverInfo: options.serverInfo ?? {
          name: "fieldscope-mcp-gateway",
          version: "0.1.0",
        },
      },
    };
  }

  if (rpc.method === "tools/list") {
    const visibleTools: McpToolDescriptor[] = [];

    // 1. REST-mapped tools
    for (const { connector, mapping } of restRegistry.values()) {
      if (isToolVisible(options.policies, principal, connector.id, mapping.name)) {
        visibleTools.push({
          name: mapping.name,
          description: mapping.description,
          inputSchema: mapping.inputSchema,
        });
      }
    }

    // 2. Upstream MCP server tools (namespaced as `<connectorId>__<toolName>`)
    for (const connector of mcpConnectors) {
      try {
        const upstreamTools = await fetchUpstreamMcpTools(
          connector,
          principal,
          options.tokenManager,
          fetchImpl
        );
        for (const tool of upstreamTools) {
          const exposedName = `${connector.id}__${tool.name}`;
          if (
            isToolVisible(options.policies, principal, connector.id, tool.name) ||
            isToolVisible(options.policies, principal, connector.id, exposedName)
          ) {
            visibleTools.push({
              name: exposedName,
              description: tool.description,
              inputSchema: tool.inputSchema,
            });
          }
        }
      } catch {
        // Ignore unavailable upstream MCP server during listing so other tools remain usable
      }
    }

    return {
      jsonrpc: "2.0",
      id,
      result: { tools: visibleTools },
    };
  }

  if (rpc.method === "tools/call") {
    const startTime = Date.now();
    const requestId = randomUUID();
    const params = (rpc.params ?? {}) as {
      name?: string;
      arguments?: Record<string, unknown>;
    };
    const toolName = params.name;
    const rawArgs =
      typeof params.arguments === "object" &&
      params.arguments !== null &&
      !Array.isArray(params.arguments)
        ? params.arguments
        : {};

    if (!toolName) {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32602, message: "Missing required param 'name'" },
      };
    }

    const recordAudit = (
      connectorId: string,
      method: string,
      path: string,
      partial: Omit<
        AuditEvent,
        | "timestamp"
        | "requestId"
        | "connectorId"
        | "protocol"
        | "method"
        | "path"
        | "toolName"
        | "durationMs"
      >
    ) => {
      options.onAudit?.({
        timestamp: new Date().toISOString(),
        requestId,
        connectorId,
        protocol: "mcp",
        method,
        path,
        toolName,
        durationMs: Date.now() - startTime,
        ...partial,
      });
    };

    // Case A: REST-to-MCP mapped tool
    const restTool = restRegistry.get(toolName);
    if (restTool) {
      const { connector, mapping } = restTool;
      const evaluation = evaluatePolicies(options.policies, {
        principal,
        connectorId: connector.id,
        protocol: "mcp",
        method: mapping.method,
        path: mapping.path,
        toolName,
        args: rawArgs,
      });

      if (!evaluation.allowed) {
        recordAudit(connector.id, mapping.method, mapping.path, {
          principal,
          decision: "deny",
          matchedPolicyId: evaluation.matchedPolicyId,
          reason: evaluation.reason,
        });
        return {
          jsonrpc: "2.0",
          id,
          result: {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  error: "policy_denied",
                  message: evaluation.reason,
                  policyId: evaluation.matchedPolicyId,
                  requestId,
                }),
              },
            ],
          },
        };
      }

      // Build HTTP request from enforced MCP arguments
      let resolvedPath = mapping.path;
      const queryParams: Record<string, unknown> = {};
      const bodyParams: Record<string, unknown> = {};
      const defaultLoc = ["GET", "HEAD", "DELETE"].includes(mapping.method)
        ? "query"
        : "body";

      for (const [argKey, argVal] of Object.entries(evaluation.args)) {
        const explicitLoc = mapping.paramLocation?.[argKey];
        if (explicitLoc === "path" || resolvedPath.includes(`:${argKey}`)) {
          resolvedPath = resolvedPath.replace(
            `:${argKey}`,
            encodeURIComponent(String(argVal))
          );
        } else if ((explicitLoc ?? defaultLoc) === "query") {
          queryParams[argKey] = argVal;
        } else {
          bodyParams[argKey] = argVal;
        }
      }

      const base = connector.baseUrl.endsWith("/")
        ? connector.baseUrl.slice(0, -1)
        : connector.baseUrl;
      const targetUrl = new URL(`${base}${resolvedPath}`);
      for (const [k, v] of Object.entries(queryParams)) {
        if (v !== undefined && v !== null) {
          targetUrl.searchParams.set(k, String(v));
        }
      }

      const headers: Record<string, string> = { accept: "application/json" };
      try {
        await injectUpstreamCredential(
          connector,
          principal,
          targetUrl,
          headers,
          options.tokenManager
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        recordAudit(connector.id, mapping.method, resolvedPath, {
          principal,
          decision: "error",
          matchedPolicyId: evaluation.matchedPolicyId,
          reason: msg,
        });
        return {
          jsonrpc: "2.0",
          id,
          result: {
            isError: true,
            content: [{ type: "text", text: JSON.stringify({ error: "credential_error", message: msg }) }],
          },
        };
      }

      const sendBody =
        !["GET", "HEAD"].includes(mapping.method) &&
        Object.keys(bodyParams).length > 0;
      if (sendBody) {
        headers["content-type"] = "application/json";
      }

      const upstreamRes = await fetchImpl(targetUrl, {
        method: mapping.method,
        headers,
        body: sendBody ? JSON.stringify(bodyParams) : undefined,
        signal: AbortSignal.timeout(connector.timeoutMs),
      });

      const contentType = upstreamRes.headers.get("content-type") ?? "";
      if (
        contentType.includes("application/json") ||
        contentType.includes("+json")
      ) {
        const rawJson: unknown = await upstreamRes.json();
        const fieldResult = applyFieldRules(rawJson, evaluation.responseRule);

        recordAudit(connector.id, mapping.method, resolvedPath, {
          principal,
          decision: "allow",
          matchedPolicyId: evaluation.matchedPolicyId,
          enforcedParams: evaluation.enforcedParams,
          prunedFields: fieldResult.prunedFields,
          transformedFields: fieldResult.transformedFields,
          upstreamStatus: upstreamRes.status,
        });

        return {
          jsonrpc: "2.0",
          id,
          result: {
            isError: !upstreamRes.ok,
            content: [
              {
                type: "text",
                text: JSON.stringify(fieldResult.data),
              },
            ],
            _meta: {
              requestId,
              policyId: evaluation.matchedPolicyId,
              prunedCount: fieldResult.prunedFields.length,
              transformedCount: fieldResult.transformedFields.length,
            },
          },
        };
      }

      const textBody = await upstreamRes.text();
      recordAudit(connector.id, mapping.method, resolvedPath, {
        principal,
        decision: "allow",
        matchedPolicyId: evaluation.matchedPolicyId,
        enforcedParams: evaluation.enforcedParams,
        upstreamStatus: upstreamRes.status,
      });

      return {
        jsonrpc: "2.0",
        id,
        result: {
          isError: !upstreamRes.ok,
          content: [{ type: "text", text: textBody }],
        },
      };
    }

    // Case B: Upstream MCP server proxy (`<connectorId>__<upstreamToolName>`)
    const sepIdx = toolName.indexOf("__");
    if (sepIdx > 0) {
      const connectorId = toolName.slice(0, sepIdx);
      const upstreamToolName = toolName.slice(sepIdx + 2);
      const connector = mcpConnectors.find((c) => c.id === connectorId);
      if (connector) {
        const evaluation = evaluatePolicies(options.policies, {
          principal,
          connectorId: connector.id,
          protocol: "mcp",
          method: "POST",
          path: "/mcp",
          toolName: upstreamToolName,
          args: rawArgs,
        });

        if (!evaluation.allowed) {
          recordAudit(connector.id, "POST", "/mcp", {
            principal,
            decision: "deny",
            matchedPolicyId: evaluation.matchedPolicyId,
            reason: evaluation.reason,
          });
          return {
            jsonrpc: "2.0",
            id,
            result: {
              isError: true,
              content: [
                {
                  type: "text",
                  text: JSON.stringify({
                    error: "policy_denied",
                    message: evaluation.reason,
                    policyId: evaluation.matchedPolicyId,
                  }),
                },
              ],
            },
          };
        }

        const url = new URL(connector.baseUrl);
        const headers: Record<string, string> = {
          "content-type": "application/json",
          accept: "application/json",
        };
        await injectUpstreamCredential(
          connector,
          principal,
          url,
          headers,
          options.tokenManager
        );

        const upstreamRes = await fetchImpl(url, {
          method: "POST",
          headers,
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: randomUUID(),
            method: "tools/call",
            params: {
              name: upstreamToolName,
              arguments: evaluation.args,
            },
          }),
          signal: AbortSignal.timeout(connector.timeoutMs),
        });

        const rpcRes = (await upstreamRes.json()) as JsonRpcResponse;
        const resultObj = rpcRes.result as
          | { content?: Array<{ type: string; text?: string }>; isError?: boolean }
          | undefined;

        const prunedAll = new Set<string>();
        const transformedAll = new Set<string>();

        if (resultObj?.content && evaluation.responseRule) {
          for (const item of resultObj.content) {
            if (item.type === "text" && typeof item.text === "string") {
              try {
                const parsed: unknown = JSON.parse(item.text);
                const governed = applyFieldRules(parsed, evaluation.responseRule);
                item.text = JSON.stringify(governed.data);
                for (const f of governed.prunedFields) prunedAll.add(f);
                for (const f of governed.transformedFields) transformedAll.add(f);
              } catch {
                // Leave non-JSON text untouched
              }
            }
          }
        }

        recordAudit(connector.id, "POST", "/mcp", {
          principal,
          decision: "allow",
          matchedPolicyId: evaluation.matchedPolicyId,
          enforcedParams: evaluation.enforcedParams,
          prunedFields: Array.from(prunedAll),
          transformedFields: Array.from(transformedAll),
          upstreamStatus: upstreamRes.status,
        });

        return {
          jsonrpc: "2.0",
          id,
          result: resultObj,
          error: rpcRes.error,
        };
      }
    }

    return {
      jsonrpc: "2.0",
      id,
      error: {
        code: -32601,
        message: `Unknown MCP tool '${toolName}'`,
      },
    };
  }

  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: -32601,
      message: `Unsupported MCP method '${rpc.method}'`,
    },
  };
}
