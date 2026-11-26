import type { AuditEvent } from "@fieldscope/core";

export interface AuditSink {
  record(event: AuditEvent): void;
}

export class ConsoleAuditSink implements AuditSink {
  record(event: AuditEvent): void {
    process.stdout.write(`${JSON.stringify({ type: "fieldscope_audit", ...event })}\n`);
  }
}
