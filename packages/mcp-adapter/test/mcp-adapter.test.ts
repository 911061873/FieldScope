import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AuditEvent, Connector, Policy, Principal } from "@fieldscope/core";
import { handleMcpRequest } from "../src/index.ts";

describe("@fieldscope/mcp-adapter", () => {
  const engUser: Principal = {
    userId: "emp-101",
    roles: ["employee"],
    attributes: { department: "engineering", projectKey: "ENG" },
    agentId: "cursor-client",
  };

  const connectors: Connector[] = [
    {
      id: "jira-prod",
      protocol: "http",
      baseUrl: "https://jira.internal",
      auth: { type: "bearer", token: "jira-service-secret" },
      timeoutMs: 5000,
      mcpTools: [
        {
          name: "jira_search_issues",
          description: "Search Jira issues",
          method: "GET",
          path: "/rest/api/3/search",
          inputSchema: { type: "object", properties: { project: { type: "string" } } },
        },
        {
          name: "jira_delete_issue",
          description: "Delete Jira issue",
          method: "DELETE",
          path: "/rest/api/3/issue/:key",
          inputSchema: { type: "object", properties: { key: { type: "string" } } },
        },
      ],
    },
  ];

  const policies: Policy[] = [
    {
      id: "mcp-eng-jira-read",
      effect: "allow",
      priority: 100,
      match: {
        principal: { roles: ["employee"], attributes: { department: "engineering" } },
        connector: "jira-prod",
      },
      action: {
        protocol: "mcp",
        methods: ["*"],
        paths: ["/**"],
        tools: ["jira_search_*"],
      },
      request: {
        validate: [
          {
            expr: "args.maxResults == null || args.maxResults <= 50",
            message: "maxResults must be <= 50",
          },
        ],
        enforce: {
          "args.project": "{{ principal.attributes.projectKey }}",
        },
      },
      response: {
        mode: "allowlist",
        fields: ["issues[*].key", "issues[*].email"],
        transforms: [{ path: "issues[*].email", action: "mask_email" }],
      },
    },
  ];

  it("handles initialize and filters tools/list based on principal permissions", async () => {
    const initRes = await handleMcpRequest(
      { jsonrpc: "2.0", id: 1, method: "initialize" },
      engUser,
      { connectors, policies }
    );
    assert.equal(initRes?.id, 1);
    assert.ok((initRes?.result as { protocolVersion: string }).protocolVersion);

    const listRes = await handleMcpRequest(
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      engUser,
      { connectors, policies }
    );
    const tools = (listRes?.result as { tools: Array<{ name: string }> }).tools;
    assert.deepEqual(
      tools.map((t) => t.name),
      ["jira_search_issues"]
    );
  });

  it("enforces args, injects upstream auth, and prunes/masks JSON response on tools/call", async () => {
    let capturedUrl = "";
    let capturedAuth = "";
    const audits: AuditEvent[] = [];

    const mockFetch: typeof fetch = async (input, init) => {
      capturedUrl = String(input);
      const h = (init?.headers ?? {}) as Record<string, string>;
      capturedAuth = h["authorization"] ?? "";
      return new Response(
        JSON.stringify({
          secretField: "hidden",
          issues: [
            {
              key: "ENG-9",
              salary: 100000,
              email: "alice@company.com",
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };

    const callRes = await handleMcpRequest(
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "jira_search_issues",
          arguments: { project: "FINANCE", maxResults: 10 },
        },
      },
      engUser,
      {
        connectors,
        policies,
        fetchImpl: mockFetch,
        onAudit: (e) => audits.push(e),
      }
    );

    assert.match(capturedUrl, /project=ENG/);
    assert.equal(capturedAuth, "Bearer jira-service-secret");

    const result = callRes?.result as {
      isError: boolean;
      content: Array<{ type: string; text: string }>;
    };
    assert.equal(result.isError, false);
    assert.deepEqual(JSON.parse(result.content[0].text), {
      issues: [{ key: "ENG-9", email: "al***@company.com" }],
    });

    assert.equal(audits.length, 1);
    assert.equal(audits[0].protocol, "mcp");
    assert.equal(audits[0].toolName, "jira_search_issues");
    assert.deepEqual(audits[0].enforcedParams, ["args.project"]);
  });

  it("returns AI-friendly isError when calling unauthorized tool or invalid args", async () => {
    const deniedTool = await handleMcpRequest(
      {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: { name: "jira_delete_issue", arguments: { key: "ENG-9" } },
      },
      engUser,
      { connectors, policies }
    );

    const resObj = deniedTool?.result as {
      isError: boolean;
      content: Array<{ text: string }>;
    };
    assert.equal(resObj.isError, true);
    assert.match(resObj.content[0].text, /policy_denied/);
  });
});
