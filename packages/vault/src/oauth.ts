import type { Connector, ConnectorAuth, Principal } from "@fieldscope/core";
import type { CredentialStore, StoredOAuthToken } from "./store.ts";

const REFRESH_BUFFER_MS = 60_000;

export interface OAuthRefreshOptions {
  fetchImpl?: typeof fetch;
  now?: () => number;
}

/**
 * Manages per-user OAuth 2.0 tokens with automatic expiration checks,
 * single-flight refresh deduplication, and encrypted persistence.
 */
export class OAuthTokenManager {
  private readonly store: CredentialStore;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly inflightRefreshes = new Map<
    string,
    Promise<StoredOAuthToken>
  >();

  constructor(store: CredentialStore, options: OAuthRefreshOptions = {}) {
    this.store = store;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => Date.now());
  }

  async setUserToken(
    userId: string,
    connectorId: string,
    token: StoredOAuthToken
  ): Promise<void> {
    await this.store.setOAuthToken(userId, connectorId, token);
  }

  async getValidAccessToken(
    userId: string,
    connector: Connector
  ): Promise<string | null> {
    if (connector.auth.type !== "oauth_delegated") {
      throw new Error(
        `Connector '${connector.id}' is not configured with oauth_delegated auth`
      );
    }

    const stored = await this.store.getOAuthToken(userId, connector.id);
    if (!stored) return null;

    const isExpiring =
      typeof stored.expiresAt === "number" &&
      stored.expiresAt - this.now() <= REFRESH_BUFFER_MS;

    if (!isExpiring) {
      return stored.accessToken;
    }

    if (!stored.refreshToken) {
      return null;
    }

    const refreshKey = `${userId}::${connector.id}`;
    let pending = this.inflightRefreshes.get(refreshKey);
    if (!pending) {
      pending = this.refreshToken(userId, connector, stored).finally(() => {
        this.inflightRefreshes.delete(refreshKey);
      });
      this.inflightRefreshes.set(refreshKey, pending);
    }

    const refreshed = await pending;
    return refreshed.accessToken;
  }

  private async refreshToken(
    userId: string,
    connector: Connector,
    current: StoredOAuthToken
  ): Promise<StoredOAuthToken> {
    if (connector.auth.type !== "oauth_delegated") {
      throw new Error("Invalid auth type for refresh");
    }

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: current.refreshToken!,
      client_id: connector.auth.clientId,
      client_secret: connector.auth.clientSecret,
    });
    if (connector.auth.scope) {
      body.set("scope", connector.auth.scope);
    }

    const res = await this.fetchImpl(connector.auth.tokenUrl, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: body.toString(),
    });

    if (!res.ok) {
      throw new Error(
        `OAuth token refresh failed for connector '${connector.id}' with status ${res.status}`
      );
    }

    const json = (await res.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
      token_type?: string;
      scope?: string;
    };

    if (!json.access_token) {
      throw new Error(
        `OAuth token refresh response missing access_token for connector '${connector.id}'`
      );
    }

    const updated: StoredOAuthToken = {
      accessToken: json.access_token,
      refreshToken: json.refresh_token ?? current.refreshToken,
      expiresAt:
        typeof json.expires_in === "number"
          ? this.now() + json.expires_in * 1000
          : undefined,
      tokenType: json.token_type ?? current.tokenType ?? "Bearer",
      scope: json.scope ?? current.scope,
    };

    await this.store.setOAuthToken(userId, connector.id, updated);
    return updated;
  }
}

function applyStaticAuth(
  auth: Exclude<ConnectorAuth, { type: "oauth_delegated" }>,
  url: URL,
  headers: Record<string, string>
): void {
  switch (auth.type) {
    case "none":
      break;
    case "bearer":
      headers["authorization"] = `Bearer ${auth.token}`;
      break;
    case "header":
      headers[auth.headerName.toLowerCase()] = auth.value;
      break;
    case "query":
      url.searchParams.set(auth.paramName, auth.value);
      break;
    case "basic": {
      const encoded = Buffer.from(
        `${auth.username}:${auth.password}`
      ).toString("base64");
      headers["authorization"] = `Basic ${encoded}`;
      break;
    }
  }
}

/**
 * Injects either a managed Service Account credential or a delegated per-user OAuth token
 * (with automatic refresh and optional fallback) into the upstream request.
 */
export async function injectUpstreamCredential(
  connector: Connector,
  principal: Principal,
  url: URL,
  headers: Record<string, string>,
  tokenManager?: OAuthTokenManager
): Promise<void> {
  if (connector.auth.type !== "oauth_delegated") {
    applyStaticAuth(connector.auth, url, headers);
    return;
  }

  if (tokenManager) {
    const accessToken = await tokenManager.getValidAccessToken(
      principal.userId,
      connector
    );
    if (accessToken) {
      headers["authorization"] = `Bearer ${accessToken}`;
      return;
    }
  }

  if (connector.auth.fallbackAuth) {
    applyStaticAuth(connector.auth.fallbackAuth, url, headers);
    return;
  }

  throw new Error(
    `No valid delegated OAuth token found for user '${principal.userId}' on connector '${connector.id}'`
  );
}
