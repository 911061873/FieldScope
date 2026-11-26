import { createHmac, timingSafeEqual } from "node:crypto";
import {
  validatePrincipal,
  type GatewayAuthConfig,
  type Principal,
} from "@fieldscope/core";

export interface AuthResult {
  ok: true;
  principal: Principal;
}

export interface AuthError {
  ok: false;
  message: string;
}

function base64UrlEncode(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64UrlDecode(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad =
    normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, "base64");
}

/**
 * Signs an HS256 JWT token for local testing and development.
 */
export function signHs256Jwt(
  payload: Record<string, unknown>,
  secret: string
): string {
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64UrlEncode(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const sig = base64UrlEncode(
    createHmac("sha256", secret).update(data).digest()
  );
  return `${data}.${sig}`;
}

function verifyHs256Jwt(
  token: string,
  secret: string
): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed JWT token");
  }
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(base64UrlDecode(headerB64).toString("utf-8")) as {
    alg?: string;
  };
  if (header.alg !== "HS256") {
    throw new Error(`Unsupported JWT algorithm: ${header.alg ?? "unknown"}`);
  }

  const expectedSig = createHmac("sha256", secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest();
  const actualSig = base64UrlDecode(sigB64);

  if (
    expectedSig.length !== actualSig.length ||
    !timingSafeEqual(expectedSig, actualSig)
  ) {
    throw new Error("Invalid JWT signature");
  }

  const payload = JSON.parse(
    base64UrlDecode(payloadB64).toString("utf-8")
  ) as Record<string, unknown>;

  if (typeof payload.exp === "number" && Date.now() / 1000 > payload.exp) {
    throw new Error("JWT token has expired");
  }

  return payload;
}

function getHeaderString(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const val = headers[name.toLowerCase()];
  if (Array.isArray(val)) return val[0];
  return val;
}

export function resolvePrincipal(
  headers: Record<string, string | string[] | undefined>,
  authConfig: GatewayAuthConfig
): AuthResult | AuthError {
  if (authConfig.mode === "jwt") {
    if (!authConfig.jwtSecret) {
      return { ok: false, message: "Gateway JWT secret is not configured" };
    }
    const authHeader = getHeaderString(headers, "authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return { ok: false, message: "Missing Bearer JWT in Authorization header" };
    }
    const token = authHeader.slice("Bearer ".length).trim();
    try {
      const claims = verifyHs256Jwt(token, authConfig.jwtSecret);
      const principal = validatePrincipal({
        userId: claims.sub ?? claims.userId,
        roles: Array.isArray(claims.roles) ? claims.roles : [],
        attributes:
          typeof claims.attributes === "object" && claims.attributes !== null
            ? claims.attributes
            : {},
        agentId: typeof claims.agentId === "string" ? claims.agentId : undefined,
      });
      return { ok: true, principal };
    } catch (err) {
      return {
        ok: false,
        message: err instanceof Error ? err.message : "JWT verification failed",
      };
    }
  }

  const prefix = authConfig.headerPrefix.toLowerCase();
  const userId = getHeaderString(headers, `${prefix}user-id`);
  if (!userId) {
    return {
      ok: false,
      message: `Missing required identity header '${prefix}user-id'`,
    };
  }

  const rawRoles = getHeaderString(headers, `${prefix}roles`);
  const roles = rawRoles
    ? rawRoles
        .split(",")
        .map((r) => r.trim())
        .filter(Boolean)
    : [];

  const agentId = getHeaderString(headers, `${prefix}agent-id`);
  const rawAttrs = getHeaderString(headers, `${prefix}attributes`);
  let attributes: Record<string, unknown> = {};
  if (rawAttrs) {
    try {
      const parsedAttrs = JSON.parse(rawAttrs);
      if (
        typeof parsedAttrs === "object" &&
        parsedAttrs !== null &&
        !Array.isArray(parsedAttrs)
      ) {
        attributes = parsedAttrs as Record<string, unknown>;
      }
    } catch {
      return {
        ok: false,
        message: `Invalid JSON in '${prefix}attributes' header`,
      };
    }
  }

  try {
    const principal = validatePrincipal({
      userId,
      roles,
      attributes,
      agentId,
    });
    return { ok: true, principal };
  } catch (err) {
    return {
      ok: false,
      message: err instanceof Error ? err.message : "Invalid principal",
    };
  }
}
