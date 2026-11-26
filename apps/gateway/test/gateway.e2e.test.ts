import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { AuditEvent, GatewayConfig } from "@fieldscope/core";
import { createGatewayServer } from "../src/server.ts";
import { signHs256Jwt } from "../src/auth.ts";

describe("@fieldscope/gateway end-to-end", () => {
  let mockUpstream: Server;
  let upstreamUrl: string;
  let lastUpstreamRequest: {
    url: string;
    headers: Record<string, unknown>;
    query: Record<string, string>;
  } | null = null;

  before(async () => {
    mockUpstream = createServer((req, res) => {
      const parsedUrl = new URL(req.url ?? "/", "http://127.0.0.1");
      const query: Record<string, string> = {};
      for (const [k, v] of parsedUrl.searchParams.entries()) {
        query[k] = v;
      }

      lastUpstreamRequest = {
        url: req.url ?? "",
        headers: req.headers,
        query,
      };

      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          total: 1,
          internalSecret: "do-not-expose",
          issues: [
            {
              key: "ENG-42",
              budgetCents: 999999,
              fields: {
                summary: "Upgrade AI gateway",
                status: { name: "Open", internalId: 10 },
                reporter: {
                  displayName: "Li Si",
                  emailAddress: "lisi@enterprise.com",
                },
                description:
                  "Contact 13800138000 or lisi@enterprise.com for details",
              },
            },
          ],
        })
      );
    });

    await new Promise<void>((resolve) => {
      mockUpstream.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = mockUpstream.address() as AddressInfo;
    upstreamUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      mockUpstream.close((err) => (err ? reject(err) : resolve()));
    });
  });

  function buildConfig(authMode: "header" | "jwt"): GatewayConfig {
    return {
      server: { host: "127.0.0.1", port: 0 },
      auth: {
        mode: authMode,
        jwtSecret: "super-secret-test-key",
        headerPrefix: "x-fieldscope-",
      },
      connectors: [
        {
          id: "jira-prod",
          protocol: "http",
          baseUrl: upstreamUrl,
          auth: {
            type: "bearer",
            token: "real-upstream-jira-secret",
          },
          timeoutMs: 5000,
        },
      ],
      policies: [
        {
          id: "policy-jira-eng-read",
          effect: "allow",
          priority: 100,
          match: {
            principal: {
              roles: ["employee"],
              attributes: { department: "engineering" },
            },
            connector: "jira-prod",
          },
          action: {
            protocol: "http",
            methods: ["GET"],
            paths: ["/rest/api/3/search"],
          },
          request: {
            validate: [
              {
                expr: "query.maxResults == null || query.maxResults <= 50",
                message: "maxResults must be <= 50",
              },
            ],
            enforce: {
              "query.project": "{{ principal.attributes.projectKey }}",
            },
          },
          response: {
            mode: "allowlist",
            fields: [
              "issues[*].key",
              "issues[*].fields.summary",
              "issues[*].fields.status.name",
              "issues[*].fields.reporter.displayName",
              "issues[*].fields.reporter.emailAddress",
              "issues[*].fields.description",
            ],
            transforms: [
              {
                path: "issues[*].fields.reporter.emailAddress",
                action: "mask_email",
              },
              {
                path: "issues[*].fields.description",
                action: "redact_pii",
              },
            ],
          },
        },
        {
          id: "policy-deny-delete",
          effect: "deny",
          priority: 999,
          match: { principal: {}, connector: "*" },
          action: { protocol: "http", methods: ["DELETE"], paths: ["/**"] },
        },
      ],
    };
  }

  it("proxies allowed request, enforces params, injects upstream secret, prunes & masks response, and audits", async () => {
    const audits: AuditEvent[] = [];
    const gateway = createGatewayServer({
      config: buildConfig("jwt"),
      auditSink: { record: (e) => audits.push(e) },
    });
    const gwUrl = await gateway.listen("127.0.0.1", 0);

    try {
      const token = signHs256Jwt(
        {
          sub: "emp-007",
          roles: ["employee"],
          agentId: "dify-assistant",
          attributes: { department: "engineering", projectKey: "ENG" },
        },
        "super-secret-test-key"
      );

      // AI attempts to query project=FINANCE (prompt injection attempt)
      const res = await fetch(
        `${gwUrl}/proxy/jira-prod/rest/api/3/search?project=FINANCE&maxResults=10`,
        {
          headers: { authorization: `Bearer ${token}` },
        }
      );

      assert.equal(res.status, 200);
      assert.equal(
        res.headers.get("x-fieldscope-policy"),
        "policy-jira-eng-read"
      );

      // Verify upstream received enforced project=ENG and real upstream credential (NOT the user JWT)
      assert.deepEqual(lastUpstreamRequest?.query, {
        project: "ENG",
        maxResults: "10",
      });
      assert.equal(
        lastUpstreamRequest?.headers["authorization"],
        "Bearer real-upstream-jira-secret"
      );

      // Verify response was pruned and masked
      const json = await res.json();
      assert.deepEqual(json, {
        issues: [
          {
            key: "ENG-42",
            fields: {
              summary: "Upgrade AI gateway",
              status: { name: "Open" },
              reporter: {
                displayName: "Li Si",
                emailAddress: "li***@enterprise.com",
              },
              description:
                "Contact [REDACTED_PHONE] or [REDACTED_EMAIL] for details",
            },
          },
        ],
      });

      // Verify structured audit event
      assert.equal(audits.length, 1);
      assert.equal(audits[0].decision, "allow");
      assert.deepEqual(audits[0].enforcedParams, ["query.project"]);
      assert.ok(audits[0].prunedFields?.includes("internalSecret"));
      assert.ok(audits[0].prunedFields?.includes("issues[*].budgetCents"));
      assert.equal(audits[0].transformedFields?.length, 2);
    } finally {
      await gateway.close();
    }
  });

  it("blocks requests violating parameter policy with AI-friendly error message", async () => {
    const gateway = createGatewayServer({
      config: buildConfig("header"),
      auditSink: { record: () => {} },
    });
    const gwUrl = await gateway.listen("127.0.0.1", 0);

    try {
      const res = await fetch(
        `${gwUrl}/proxy/jira-prod/rest/api/3/search?maxResults=500`,
        {
          headers: {
            "x-fieldscope-user-id": "emp-007",
            "x-fieldscope-roles": "employee",
            "x-fieldscope-attributes": JSON.stringify({
              department: "engineering",
              projectKey: "ENG",
            }),
          },
        }
      );

      assert.equal(res.status, 403);
      const body = (await res.json()) as Record<string, unknown>;
      assert.equal(body.error, "policy_denied");
      assert.equal(body.message, "maxResults must be <= 50");
      assert.equal(body.policyId, "policy-jira-eng-read");
    } finally {
      await gateway.close();
    }
  });

  it("blocks DELETE requests via explicit deny and rejects missing identity", async () => {
    const gateway = createGatewayServer({
      config: buildConfig("header"),
      auditSink: { record: () => {} },
    });
    const gwUrl = await gateway.listen("127.0.0.1", 0);

    try {
      const unauth = await fetch(`${gwUrl}/proxy/jira-prod/rest/api/3/search`);
      assert.equal(unauth.status, 401);

      const denied = await fetch(
        `${gwUrl}/proxy/jira-prod/rest/api/3/issue/ENG-42`,
        {
          method: "DELETE",
          headers: {
            "x-fieldscope-user-id": "emp-007",
            "x-fieldscope-roles": "employee",
          },
        }
      );
      assert.equal(denied.status, 403);
      const body = (await denied.json()) as Record<string, unknown>;
      assert.equal(body.error, "policy_denied");
      assert.equal(body.policyId, "policy-deny-delete");
    } finally {
      await gateway.close();
    }
  });
});
