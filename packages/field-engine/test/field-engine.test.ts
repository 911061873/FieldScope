import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { applyFieldRules } from "../src/index.ts";

describe("@fieldscope/field-engine", () => {
  const samplePayload = {
    total: 2,
    internalAuditCode: "SECRET-999",
    issues: [
      {
        key: "ENG-101",
        internalCost: 15000,
        fields: {
          summary: "Fix auth timeout",
          status: { name: "In Progress", id: "3" },
          reporter: {
            displayName: "Zhang San",
            emailAddress: "zhangsan@corp.com",
            phone: "13812345678",
          },
          description:
            "Customer phone 13987654321, email bob@example.org, id 110105199003071234",
        },
      },
    ],
  };

  it("prunes fields with allowlist and applies masking/PII redaction without mutating input", () => {
    const originalSnapshot = structuredClone(samplePayload);

    const result = applyFieldRules(samplePayload, {
      mode: "allowlist",
      fields: [
        "issues[*].key",
        "issues[*].fields.summary",
        "issues[*].fields.status.name",
        "issues[*].fields.reporter.displayName",
        "issues[*].fields.reporter.emailAddress",
        "issues[*].fields.reporter.phone",
        "issues[*].fields.description",
      ],
      transforms: [
        { path: "issues[*].fields.reporter.emailAddress", action: "mask_email" },
        { path: "issues[*].fields.reporter.phone", action: "mask_phone" },
        { path: "issues[*].fields.description", action: "redact_pii" },
      ],
    });

    assert.deepEqual(samplePayload, originalSnapshot);

    assert.deepEqual(result.data, {
      issues: [
        {
          key: "ENG-101",
          fields: {
            summary: "Fix auth timeout",
            status: { name: "In Progress" },
            reporter: {
              displayName: "Zhang San",
              emailAddress: "zh***@corp.com",
              phone: "138****5678",
            },
            description:
              "Customer phone [REDACTED_PHONE], email [REDACTED_EMAIL], id [REDACTED_ID]",
          },
        },
      ],
    });

    assert.ok(result.prunedFields.includes("total"));
    assert.ok(result.prunedFields.includes("internalAuditCode"));
    assert.ok(result.prunedFields.includes("issues[*].internalCost"));
    assert.ok(result.prunedFields.includes("issues[*].fields.status.id"));
    assert.deepEqual(result.transformedFields, [
      "issues[*].fields.reporter.emailAddress",
      "issues[*].fields.reporter.phone",
      "issues[*].fields.description",
    ]);
  });

  it("removes sensitive fields in denylist mode and supports hash/redact/mask_middle", () => {
    const result = applyFieldRules(
      {
        user: {
          id: "u-1",
          ssn: "123-45-6789",
          token: "sk-live-secret-token",
          nick: "Alexander",
        },
      },
      {
        mode: "denylist",
        fields: ["user.ssn"],
        transforms: [
          { path: "user.token", action: "redact" },
          { path: "user.id", action: "hash" },
          { path: "user.nick", action: "mask_middle" },
        ],
      }
    );

    const data = result.data as {
      user: { id: string; ssn?: string; token: string; nick: string };
    };
    assert.equal(data.user.ssn, undefined);
    assert.equal(data.user.token, "[REDACTED]");
    assert.match(data.user.id, /^sha256:[0-9a-f]{16}$/);
    assert.equal(data.user.nick, "Al***er");
    assert.deepEqual(result.prunedFields, ["user.ssn"]);
  });

  it("handles root-level arrays with [*] paths", () => {
    const result = applyFieldRules(
      [
        { id: 1, name: "Alice", salary: 50000 },
        { id: 2, name: "Bob", salary: 60000 },
      ],
      {
        mode: "allowlist",
        fields: ["[*].id", "[*].name"],
        transforms: [],
      }
    );

    assert.deepEqual(result.data, [
      { id: 1, name: "Alice" },
      { id: 2, name: "Bob" },
    ]);
    assert.deepEqual(result.prunedFields, ["[*].salary"]);
  });
});
