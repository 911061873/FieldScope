export type PrimitiveValue = string | number | boolean | null;

export interface Principal {
  userId: string;
  roles: string[];
  attributes: Record<string, unknown>;
  agentId?: string;
}

export type HttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "HEAD"
  | "OPTIONS"
  | "*";

export type ConnectorAuth =
  | { type: "none" }
  | { type: "bearer"; token: string }
  | { type: "header"; headerName: string; value: string }
  | { type: "query"; paramName: string; value: string }
  | { type: "basic"; username: string; password: string }
  | {
      type: "oauth_delegated";
      tokenUrl: string;
      clientId: string;
      clientSecret: string;
      scope?: string;
      fallbackAuth?: Exclude<ConnectorAuth, { type: "oauth_delegated" }>;
    };

export interface McpToolMapping {
  name: string;
  description: string;
  method: Exclude<HttpMethod, "*">;
  path: string;
  inputSchema: Record<string, unknown>;
  /**
   * Maps tool argument names to where they should be placed in the HTTP request.
   * Defaults to "query" for GET/HEAD/DELETE and "body" for POST/PUT/PATCH.
   */
  paramLocation?: Record<string, "path" | "query" | "body">;
}

export interface Connector {
  id: string;
  name?: string;
  protocol: "http" | "mcp";
  baseUrl: string;
  auth: ConnectorAuth;
  timeoutMs: number;
  mcpTools?: McpToolMapping[];
}

export type FieldTransformAction =
  | "mask_email"
  | "mask_phone"
  | "mask_middle"
  | "hash"
  | "redact"
  | "redact_pii";

export interface FieldTransformRule {
  path: string;
  action: FieldTransformAction;
}

export interface ResponseRule {
  mode: "allowlist" | "denylist";
  fields: string[];
  transforms: FieldTransformRule[];
}

export interface RequestValidationRule {
  expr: string;
  message: string;
}

export interface RequestRule {
  validate: RequestValidationRule[];
  enforce: Record<string, unknown>;
}

export interface PrincipalMatch {
  userIds?: string[];
  roles?: string[];
  agentIds?: string[];
  attributes?: Record<string, unknown>;
}

export interface PolicyAction {
  protocol: "http" | "mcp";
  methods: HttpMethod[];
  paths: string[];
  tools?: string[];
}

export interface Policy {
  id: string;
  name?: string;
  effect: "allow" | "deny";
  priority: number;
  match: {
    principal: PrincipalMatch;
    connector: string;
  };
  action: PolicyAction;
  request?: RequestRule;
  response?: ResponseRule;
}

export interface GatewayAuthConfig {
  mode: "header" | "jwt";
  jwtSecret?: string;
  headerPrefix: string;
}

export interface GatewayVaultConfig {
  masterKey?: string;
  sqlitePath?: string;
}

export interface GatewayConfig {
  server: {
    host: string;
    port: number;
  };
  auth: GatewayAuthConfig;
  vault?: GatewayVaultConfig;
  connectors: Connector[];
  policies: Policy[];
}

export interface AuditEvent {
  timestamp: string;
  requestId: string;
  principal: Principal | null;
  connectorId: string;
  protocol?: "http" | "mcp";
  method: string;
  path: string;
  toolName?: string;
  decision: "allow" | "deny" | "error";
  matchedPolicyId?: string;
  reason?: string;
  enforcedParams?: string[];
  prunedFields?: string[];
  transformedFields?: string[];
  upstreamStatus?: number;
  durationMs: number;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function validatePrincipal(input: unknown): Principal {
  if (!isObject(input)) {
    throw new Error("Principal must be an object");
  }
  if (typeof input.userId !== "string" || input.userId.trim() === "") {
    throw new Error("Principal.userId must be a non-empty string");
  }
  const roles =
    input.roles === undefined
      ? []
      : Array.isArray(input.roles) &&
          input.roles.every((r) => typeof r === "string")
        ? (input.roles as string[])
        : (() => {
            throw new Error("Principal.roles must be an array of strings");
          })();

  const attributes =
    input.attributes === undefined
      ? {}
      : isObject(input.attributes)
        ? input.attributes
        : (() => {
            throw new Error("Principal.attributes must be a plain object");
          })();

  const agentId =
    input.agentId === undefined
      ? undefined
      : typeof input.agentId === "string"
        ? input.agentId
        : (() => {
            throw new Error("Principal.agentId must be a string");
          })();

  return { userId: input.userId, roles, attributes, agentId };
}

export function validateGatewayConfig(input: unknown): GatewayConfig {
  if (!isObject(input)) {
    throw new Error("Gateway config must be an object");
  }

  const rawServer = isObject(input.server) ? input.server : {};
  const host = typeof rawServer.host === "string" ? rawServer.host : "0.0.0.0";
  const port = typeof rawServer.port === "number" ? rawServer.port : 8080;

  const rawAuth = isObject(input.auth) ? input.auth : {};
  const authMode = rawAuth.mode === "jwt" ? "jwt" : "header";
  const headerPrefix =
    typeof rawAuth.headerPrefix === "string"
      ? rawAuth.headerPrefix
      : "x-fieldscope-";
  const jwtSecret =
    typeof rawAuth.jwtSecret === "string" ? rawAuth.jwtSecret : undefined;

  const rawVault = isObject(input.vault) ? input.vault : undefined;
  const vault: GatewayVaultConfig | undefined = rawVault
    ? {
        masterKey:
          typeof rawVault.masterKey === "string"
            ? rawVault.masterKey
            : undefined,
        sqlitePath:
          typeof rawVault.sqlitePath === "string"
            ? rawVault.sqlitePath
            : undefined,
      }
    : undefined;

  const rawConnectors = Array.isArray(input.connectors) ? input.connectors : [];
  const connectors: Connector[] = rawConnectors.map((c, idx) => {
    if (!isObject(c)) {
      throw new Error(`connectors[${idx}] must be an object`);
    }
    if (typeof c.id !== "string" || !c.id) {
      throw new Error(`connectors[${idx}].id is required`);
    }
    if (typeof c.baseUrl !== "string" || !c.baseUrl) {
      throw new Error(`connectors[${idx}].baseUrl is required`);
    }
    const auth = isObject(c.auth)
      ? (c.auth as unknown as ConnectorAuth)
      : ({ type: "none" } as const);
    return {
      id: c.id,
      name: typeof c.name === "string" ? c.name : undefined,
      protocol: c.protocol === "mcp" ? "mcp" : "http",
      baseUrl: c.baseUrl,
      auth,
      timeoutMs: typeof c.timeoutMs === "number" ? c.timeoutMs : 15000,
      mcpTools: Array.isArray(c.mcpTools)
        ? (c.mcpTools as McpToolMapping[])
        : undefined,
    };
  });

  const rawPolicies = Array.isArray(input.policies) ? input.policies : [];
  const policies: Policy[] = rawPolicies.map((p, idx) => {
    if (!isObject(p)) {
      throw new Error(`policies[${idx}] must be an object`);
    }
    if (typeof p.id !== "string" || !p.id) {
      throw new Error(`policies[${idx}].id is required`);
    }
    if (!isObject(p.match) || typeof p.match.connector !== "string") {
      throw new Error(`policies[${idx}].match.connector is required`);
    }
    const rawAction = isObject(p.action) ? p.action : {};
    const rawRequest = isObject(p.request) ? p.request : undefined;
    const rawResponse = isObject(p.response) ? p.response : undefined;

    return {
      id: p.id,
      name: typeof p.name === "string" ? p.name : undefined,
      effect: p.effect === "deny" ? "deny" : "allow",
      priority: typeof p.priority === "number" ? p.priority : 100,
      match: {
        principal: isObject(p.match.principal)
          ? (p.match.principal as PrincipalMatch)
          : {},
        connector: p.match.connector,
      },
      action: {
        protocol: rawAction.protocol === "mcp" ? "mcp" : "http",
        methods: Array.isArray(rawAction.methods)
          ? (rawAction.methods as HttpMethod[])
          : ["*"],
        paths: Array.isArray(rawAction.paths)
          ? (rawAction.paths as string[])
          : ["/**"],
        tools: Array.isArray(rawAction.tools)
          ? (rawAction.tools as string[])
          : undefined,
      },
      request: rawRequest
        ? {
            validate: Array.isArray(rawRequest.validate)
              ? (rawRequest.validate as RequestValidationRule[])
              : [],
            enforce: isObject(rawRequest.enforce) ? rawRequest.enforce : {},
          }
        : undefined,
      response: rawResponse
        ? {
            mode: rawResponse.mode === "denylist" ? "denylist" : "allowlist",
            fields: Array.isArray(rawResponse.fields)
              ? (rawResponse.fields as string[])
              : [],
            transforms: Array.isArray(rawResponse.transforms)
              ? (rawResponse.transforms as FieldTransformRule[])
              : [],
          }
        : undefined,
    };
  });

  return {
    server: { host, port },
    auth: { mode: authMode, jwtSecret, headerPrefix },
    vault,
    connectors,
    policies,
  };
}
