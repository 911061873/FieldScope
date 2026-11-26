import { randomUUID } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import type { AuditEvent, Connector, GatewayConfig } from "@fieldscope/core";
import { applyFieldRules } from "@fieldscope/field-engine";
import {
  handleMcpRequest,
  type JsonRpcRequest,
} from "@fieldscope/mcp-adapter";
import { evaluatePolicies } from "@fieldscope/policy-engine";
import {
  CredentialCipher,
  InMemoryCredentialStore,
  OAuthTokenManager,
  SqliteCredentialStore,
  injectUpstreamCredential,
  type CredentialStore,
} from "@fieldscope/vault";
import { ConsoleAuditSink, type AuditSink } from "./audit.ts";
import { resolvePrincipal } from "./auth.ts";

export interface CreateGatewayOptions {
  config: GatewayConfig;
  auditSink?: AuditSink;
  tokenManager?: OAuthTokenManager;
}

export interface GatewayServer {
  server: Server;
  tokenManager: OAuthTokenManager;
  listen(host?: string, port?: number): Promise<string>;
  close(): Promise<void>;
}

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "authorization",
]);

function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {}
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    ...extraHeaders,
  });
  res.end(payload);
}

async function readRequestBody(req: IncomingMessage): Promise<unknown> {
  const method = (req.method ?? "GET").toUpperCase();
  if (method === "GET" || method === "HEAD") {
    return undefined;
  }

  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  if (chunks.length === 0) return undefined;

  const raw = Buffer.concat(chunks).toString("utf-8");
  const ct = req.headers["content-type"] ?? "";
  if (ct.includes("application/json")) {
    return JSON.parse(raw) as unknown;
  }
  return raw;
}

function createDefaultVault(config: GatewayConfig): {
  store: CredentialStore;
  tokenManager: OAuthTokenManager;
} {
  const masterKey =
    config.vault?.masterKey ??
    process.env.FIELDSCOPE_VAULT_KEY ??
    "fieldscope-dev-ephemeral-master-key";
  const cipher = new CredentialCipher(masterKey);
  const store: CredentialStore = config.vault?.sqlitePath
    ? new SqliteCredentialStore(config.vault.sqlitePath, cipher)
    : new InMemoryCredentialStore(cipher);
  return { store, tokenManager: new OAuthTokenManager(store) };
}

export function createGatewayServer(
  options: CreateGatewayOptions
): GatewayServer {
  const { config, auditSink = new ConsoleAuditSink() } = options;

  let ownedStore: CredentialStore | undefined;
  let tokenManager: OAuthTokenManager;
  if (options.tokenManager) {
    tokenManager = options.tokenManager;
  } else {
    const created = createDefaultVault(config);
    ownedStore = created.store;
    tokenManager = created.tokenManager;
  }

  const connectorMap = new Map<string, Connector>();
  for (const connector of config.connectors) {
    connectorMap.set(connector.id, connector);
  }

  const server = createServer(async (req, res) => {
    const startTime = Date.now();
    const requestId = randomUUID();
    const method = (req.method ?? "GET").toUpperCase();
    const reqUrl = new URL(req.url ?? "/", "http://localhost");
    const pathname = reqUrl.pathname;

    if (method === "GET" && pathname === "/health") {
      return sendJson(res, 200, {
        status: "ok",
        protocols: ["http", "mcp"],
        connectors: config.connectors.length,
        policies: config.policies.length,
      });
    }

    // MCP Streamable HTTP endpoint (JSON-RPC 2.0)
    if (method === "POST" && pathname === "/mcp") {
      const authResult = resolvePrincipal(req.headers, config.auth);
      if (!authResult.ok) {
        auditSink.record({
          timestamp: new Date().toISOString(),
          requestId,
          principal: null,
          connectorId: "mcp",
          protocol: "mcp",
          method,
          path: pathname,
          decision: "deny",
          reason: authResult.message,
          durationMs: Date.now() - startTime,
        });
        return sendJson(res, 401, {
          jsonrpc: "2.0",
          id: null,
          error: { code: -32001, message: authResult.message },
        });
      }

      let body: unknown;
      try {
        body = await readRequestBody(req);
      } catch {
        return sendJson(res, 400, {
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error: invalid JSON" },
        });
      }

      if (typeof body !== "object" || body === null) {
        return sendJson(res, 400, {
          jsonrpc: "2.0",
          id: null,
          error: { code: -32600, message: "Invalid Request" },
        });
      }

      const rpcResponse = await handleMcpRequest(
        body as JsonRpcRequest,
        authResult.principal,
        {
          connectors: config.connectors,
          policies: config.policies,
          tokenManager,
          onAudit: (event) => auditSink.record(event),
        }
      );

      if (rpcResponse === null) {
        res.writeHead(202);
        res.end();
        return;
      }

      return sendJson(res, 200, rpcResponse, {
        "x-fieldscope-request-id": requestId,
      });
    }

    // HTTP Reverse Proxy endpoint
    const proxyMatch = pathname.match(/^\/proxy\/([^/]+)(\/.*)?$/);
    if (!proxyMatch) {
      return sendJson(res, 404, {
        error: "not_found",
        message:
          "Use /proxy/:connectorId/* for HTTP proxy or POST /mcp for MCP gateway",
        requestId,
      });
    }

    const connectorId = decodeURIComponent(proxyMatch[1]);
    const upstreamPath = proxyMatch[2] || "/";

    const recordAudit = (
      partial: Omit<
        AuditEvent,
        | "timestamp"
        | "requestId"
        | "connectorId"
        | "protocol"
        | "method"
        | "path"
        | "durationMs"
      >
    ) => {
      auditSink.record({
        timestamp: new Date().toISOString(),
        requestId,
        connectorId,
        protocol: "http",
        method,
        path: upstreamPath,
        durationMs: Date.now() - startTime,
        ...partial,
      });
    };

    const connector = connectorMap.get(connectorId);
    if (!connector) {
      recordAudit({
        principal: null,
        decision: "deny",
        reason: `Unknown connector '${connectorId}'`,
      });
      return sendJson(res, 404, {
        error: "connector_not_found",
        message: `Connector '${connectorId}' is not registered in FieldScope`,
        requestId,
      });
    }

    // 1. Identity resolution
    const authResult = resolvePrincipal(req.headers, config.auth);
    if (!authResult.ok) {
      recordAudit({
        principal: null,
        decision: "deny",
        reason: authResult.message,
      });
      return sendJson(res, 401, {
        error: "unauthorized",
        message: authResult.message,
        requestId,
      });
    }

    const principal = authResult.principal;

    const queryObj: Record<string, unknown> = {};
    for (const [k, v] of reqUrl.searchParams.entries()) {
      if (k in queryObj) {
        const existing = queryObj[k];
        queryObj[k] = Array.isArray(existing) ? [...existing, v] : [existing, v];
      } else {
        queryObj[k] = v;
      }
    }

    let requestBody: unknown;
    try {
      requestBody = await readRequestBody(req);
    } catch {
      recordAudit({
        principal,
        decision: "error",
        reason: "Invalid JSON request body",
      });
      return sendJson(res, 400, {
        error: "invalid_body",
        message: "Request body is not valid JSON",
        requestId,
      });
    }

    // 2. Policy evaluation
    const evaluation = evaluatePolicies(config.policies, {
      principal,
      connectorId,
      protocol: "http",
      method,
      path: upstreamPath,
      query: queryObj,
      body: requestBody,
    });

    if (!evaluation.allowed) {
      recordAudit({
        principal,
        decision: "deny",
        matchedPolicyId: evaluation.matchedPolicyId,
        reason: evaluation.reason,
      });
      return sendJson(res, 403, {
        error: "policy_denied",
        message: evaluation.reason,
        policyId: evaluation.matchedPolicyId,
        requestId,
      });
    }

    // 3. Build upstream request with enforced params and hybrid credential injection
    const base = connector.baseUrl.endsWith("/")
      ? connector.baseUrl.slice(0, -1)
      : connector.baseUrl;
    const targetUrl = new URL(`${base}${upstreamPath}`);

    for (const [k, v] of Object.entries(evaluation.query)) {
      if (v === undefined || v === null) continue;
      if (Array.isArray(v)) {
        for (const item of v) {
          targetUrl.searchParams.append(k, String(item));
        }
      } else {
        targetUrl.searchParams.set(k, String(v));
      }
    }

    const forwardHeaders: Record<string, string> = {};
    const internalPrefix = config.auth.headerPrefix.toLowerCase();
    for (const [key, val] of Object.entries(req.headers)) {
      const lower = key.toLowerCase();
      if (HOP_BY_HOP_HEADERS.has(lower) || lower.startsWith(internalPrefix)) {
        continue;
      }
      if (val !== undefined) {
        forwardHeaders[lower] = Array.isArray(val) ? val.join(", ") : val;
      }
    }

    try {
      await injectUpstreamCredential(
        connector,
        principal,
        targetUrl,
        forwardHeaders,
        tokenManager
      );
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to resolve upstream credential";
      recordAudit({
        principal,
        decision: "error",
        matchedPolicyId: evaluation.matchedPolicyId,
        reason: message,
      });
      return sendJson(res, 401, {
        error: "upstream_credential_required",
        message,
        requestId,
      });
    }

    const hasBody =
      method !== "GET" && method !== "HEAD" && evaluation.body !== undefined;
    let bodyPayload: string | undefined;
    if (hasBody) {
      bodyPayload =
        typeof evaluation.body === "string"
          ? evaluation.body
          : JSON.stringify(evaluation.body);
      if (!forwardHeaders["content-type"]) {
        forwardHeaders["content-type"] = "application/json";
      }
    }

    // 4. Proxy to upstream third-party API
    let upstreamRes: Response;
    try {
      upstreamRes = await fetch(targetUrl, {
        method,
        headers: forwardHeaders,
        body: bodyPayload,
        signal: AbortSignal.timeout(connector.timeoutMs),
      });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Upstream request failed";
      recordAudit({
        principal,
        decision: "error",
        matchedPolicyId: evaluation.matchedPolicyId,
        enforcedParams: evaluation.enforcedParams,
        reason: message,
      });
      return sendJson(res, 502, {
        error: "upstream_error",
        message: `Failed to reach upstream '${connectorId}': ${message}`,
        requestId,
      });
    }

    // 5. Apply FieldScope response pruning & masking on JSON responses
    const contentType = upstreamRes.headers.get("content-type") ?? "";
    const isJson =
      contentType.includes("application/json") || contentType.includes("+json");

    if (isJson) {
      const rawJson: unknown = await upstreamRes.json();
      const fieldResult = applyFieldRules(rawJson, evaluation.responseRule);

      recordAudit({
        principal,
        decision: "allow",
        matchedPolicyId: evaluation.matchedPolicyId,
        enforcedParams: evaluation.enforcedParams,
        prunedFields: fieldResult.prunedFields,
        transformedFields: fieldResult.transformedFields,
        upstreamStatus: upstreamRes.status,
      });

      const extraHeaders: Record<string, string> = {
        "x-fieldscope-request-id": requestId,
        "x-fieldscope-pruned-count": String(fieldResult.prunedFields.length),
        "x-fieldscope-transformed-count": String(
          fieldResult.transformedFields.length
        ),
      };
      if (evaluation.matchedPolicyId) {
        extraHeaders["x-fieldscope-policy"] = evaluation.matchedPolicyId;
      }

      return sendJson(res, upstreamRes.status, fieldResult.data, extraHeaders);
    }

    const rawBuffer = Buffer.from(await upstreamRes.arrayBuffer());
    recordAudit({
      principal,
      decision: "allow",
      matchedPolicyId: evaluation.matchedPolicyId,
      enforcedParams: evaluation.enforcedParams,
      upstreamStatus: upstreamRes.status,
    });

    const passthroughHeaders: Record<string, string> = {
      "x-fieldscope-request-id": requestId,
    };
    if (contentType) {
      passthroughHeaders["content-type"] = contentType;
    }
    res.writeHead(upstreamRes.status, passthroughHeaders);
    res.end(rawBuffer);
  });

  return {
    server,
    tokenManager,
    listen(host = config.server.host, port = config.server.port) {
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          const addr = server.address() as AddressInfo;
          resolve(`http://${addr.address}:${addr.port}`);
        });
      });
    },
    close() {
      return new Promise((resolve, reject) => {
        server.close((err) => {
          ownedStore?.close?.();
          if (err) reject(err);
          else resolve();
        });
      });
    },
  };
}
