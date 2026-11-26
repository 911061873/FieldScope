import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Connector, Principal } from "@fieldscope/core";
import {
  CredentialCipher,
  InMemoryCredentialStore,
  OAuthTokenManager,
  SqliteCredentialStore,
  injectUpstreamCredential,
} from "../src/index.ts";

describe("@fieldscope/vault", () => {
  it("encrypts and decrypts with AES-256-GCM and rejects tampered ciphertext", () => {
    const cipher = new CredentialCipher("my-enterprise-master-secret");
    const secret = JSON.stringify({ accessToken: "tok_live_123456" });
    const encrypted = cipher.encrypt(secret);

    assert.ok(encrypted.startsWith("v1:"));
    assert.ok(!encrypted.includes("tok_live_123456"));
    assert.equal(cipher.decrypt(encrypted), secret);

    // Tamper with ciphertext
    const parts = encrypted.split(":");
    parts[3] = Buffer.from("tampered-data").toString("base64");
    assert.throws(() => cipher.decrypt(parts.join(":")));
  });

  it("persists encrypted tokens in SQLite store", async () => {
    const cipher = new CredentialCipher("sqlite-test-key");
    const store = new SqliteCredentialStore(":memory:", cipher);

    await store.setOAuthToken("user-1", "github", {
      accessToken: "gho_secret_token",
      refreshToken: "ghr_refresh_token",
      expiresAt: Date.now() + 3600_000,
    });

    const loaded = await store.getOAuthToken("user-1", "github");
    assert.equal(loaded?.accessToken, "gho_secret_token");
    assert.equal(loaded?.refreshToken, "ghr_refresh_token");

    await store.deleteOAuthToken("user-1", "github");
    assert.equal(await store.getOAuthToken("user-1", "github"), null);
    store.close();
  });

  it("auto-refreshes expiring OAuth tokens with single-flight deduplication and supports fallbackAuth", async () => {
    const cipher = new CredentialCipher("oauth-test-key");
    const store = new InMemoryCredentialStore(cipher);
    let refreshCalls = 0;

    const mockFetch: typeof fetch = async () => {
      refreshCalls++;
      return new Response(
        JSON.stringify({
          access_token: "fresh-access-token",
          refresh_token: "fresh-refresh-token",
          expires_in: 3600,
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };

    const nowMs = 1_700_000_000_000;
    const manager = new OAuthTokenManager(store, {
      fetchImpl: mockFetch,
      now: () => nowMs,
    });

    const connector: Connector = {
      id: "feishu",
      protocol: "http",
      baseUrl: "https://open.feishu.cn",
      timeoutMs: 5000,
      auth: {
        type: "oauth_delegated",
        tokenUrl: "https://open.feishu.cn/oauth/token",
        clientId: "cli_123",
        clientSecret: "sec_456",
        fallbackAuth: {
          type: "bearer",
          token: "service-account-fallback",
        },
      },
    };

    // Store an already-expiring token (expires in 10s < 60s buffer)
    await manager.setUserToken("u-1", "feishu", {
      accessToken: "stale-token",
      refreshToken: "old-refresh",
      expiresAt: nowMs + 10_000,
    });

    // Fire 3 concurrent token requests -> should deduplicate into 1 refresh call
    const [t1, t2, t3] = await Promise.all([
      manager.getValidAccessToken("u-1", connector),
      manager.getValidAccessToken("u-1", connector),
      manager.getValidAccessToken("u-1", connector),
    ]);

    assert.equal(refreshCalls, 1);
    assert.equal(t1, "fresh-access-token");
    assert.equal(t2, "fresh-access-token");
    assert.equal(t3, "fresh-access-token");

    // User without delegated token falls back to service account auth
    const userWithoutToken: Principal = {
      userId: "u-no-oauth",
      roles: ["employee"],
      attributes: {},
    };
    const headers: Record<string, string> = {};
    await injectUpstreamCredential(
      connector,
      userWithoutToken,
      new URL("https://open.feishu.cn/api/v1/docs"),
      headers,
      manager
    );
    assert.equal(headers["authorization"], "Bearer service-account-fallback");
  });
});
