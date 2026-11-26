import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Policy, Principal } from "@fieldscope/core";
import { evaluateExpression, evaluatePolicies } from "../src/index.ts";

describe("@fieldscope/policy-engine", () => {
  const engUser: Principal = {
    userId: "u-eng-01",
    roles: ["employee"],
    attributes: {
      department: "engineering",
      projectKey: "ENG",
    },
    agentId: "assistant-bot",
  };

  const policies: Policy[] = [
    {
      id: "allow-jira-read",
      name: "Allow Engineering Jira Read",
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
        methods: ["GET", "POST"],
        paths: ["/rest/api/3/search", "/rest/api/3/issue/*"],
      },
      request: {
        validate: [
          {
            expr: "query.maxResults == null || query.maxResults <= 50",
            message: "maxResults cannot exceed 50",
          },
        ],
        enforce: {
          "query.project": "{{ principal.attributes.projectKey }}",
          "body.scope.department": "{{ principal.attributes.department }}",
        },
      },
      response: {
        mode: "allowlist",
        fields: ["issues[*].key"],
        transforms: [],
      },
    },
    {
      id: "deny-all-delete",
      name: "Deny All Deletes",
      effect: "deny",
      priority: 50,
      match: {
        principal: {},
        connector: "*",
      },
      action: {
        protocol: "http",
        methods: ["DELETE"],
        paths: ["/**"],
      },
    },
    {
      id: "allow-admin-all",
      effect: "allow",
      priority: 500,
      match: {
        principal: { roles: ["admin"] },
        connector: "jira-prod",
      },
      action: {
        protocol: "http",
        methods: ["*"],
        paths: ["/**"],
      },
    },
  ];

  it("enforces default deny when no policy matches", () => {
    const res = evaluatePolicies(policies, {
      principal: {
        userId: "u-sales",
        roles: ["employee"],
        attributes: { department: "sales" },
      },
      connectorId: "jira-prod",
      method: "GET",
      path: "/rest/api/3/search",
    });

    assert.equal(res.allowed, false);
    assert.match(res.reason ?? "", /no policy allows/);
  });

  it("ensures explicit deny overrides higher-priority allow", () => {
    const admin: Principal = {
      userId: "u-admin",
      roles: ["admin"],
      attributes: {},
    };
    const res = evaluatePolicies(policies, {
      principal: admin,
      connectorId: "jira-prod",
      method: "DELETE",
      path: "/rest/api/3/issue/ENG-1",
    });

    assert.equal(res.allowed, false);
    assert.equal(res.matchedPolicyId, "deny-all-delete");
  });

  it("rejects requests that violate parameter validation expressions", () => {
    const res = evaluatePolicies(policies, {
      principal: engUser,
      connectorId: "jira-prod",
      method: "GET",
      path: "/rest/api/3/search",
      query: { maxResults: "100" },
    });

    assert.equal(res.allowed, false);
    assert.equal(res.matchedPolicyId, "allow-jira-read");
    assert.equal(res.reason, "maxResults cannot exceed 50");
  });

  it("force-injects query and nested body parameters from principal attributes", () => {
    const res = evaluatePolicies(policies, {
      principal: engUser,
      connectorId: "jira-prod",
      method: "POST",
      path: "/rest/api/3/search",
      query: { maxResults: "20", project: "FINANCE" },
      body: { jql: "status = Open" },
    });

    assert.equal(res.allowed, true);
    assert.deepEqual(res.query, { maxResults: "20", project: "ENG" });
    assert.deepEqual(res.body, {
      jql: "status = Open",
      scope: { department: "engineering" },
    });
    assert.deepEqual(res.enforcedParams, [
      "query.project",
      "body.scope.department",
    ]);
  });

  it("evaluates complex safe expressions with in, contains, startsWith, and boolean logic", () => {
    const ctx = {
      query: { env: "staging", limit: 25 },
      body: { tags: ["ai", "readonly"], path: "/public/docs" },
    };

    assert.equal(
      evaluateExpression(
        'query.env in ["dev", "staging"] && query.limit <= 50',
        ctx
      ),
      true
    );
    assert.equal(
      evaluateExpression(
        'body.tags contains "readonly" && body.path startsWith "/public/"',
        ctx
      ),
      true
    );
    assert.equal(evaluateExpression('!(query.env == "prod")', ctx), true);
  });
});
