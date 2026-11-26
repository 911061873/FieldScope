import { createHash } from "node:crypto";
import type { FieldTransformAction } from "@fieldscope/core";

const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const CN_PHONE_REGEX = /(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)/g;
const CN_ID_CARD_REGEX =
  /(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g;

export function applyTransformValue(
  value: unknown,
  action: FieldTransformAction
): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  switch (action) {
    case "redact":
      return "[REDACTED]";

    case "hash": {
      const raw = typeof value === "string" ? value : JSON.stringify(value);
      const digest = createHash("sha256").update(raw).digest("hex").slice(0, 16);
      return `sha256:${digest}`;
    }

    case "mask_email": {
      if (typeof value !== "string") return value;
      const atIndex = value.indexOf("@");
      if (atIndex <= 0) return maskMiddle(value);
      const local = value.slice(0, atIndex);
      const domain = value.slice(atIndex);
      const visible = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2);
      return `${visible}***${domain}`;
    }

    case "mask_phone": {
      if (typeof value !== "string") return value;
      const digits = value.replace(/\D/g, "");
      if (digits.length >= 7) {
        return `${value.slice(0, 3)}****${value.slice(-4)}`;
      }
      return maskMiddle(value);
    }

    case "mask_middle": {
      if (typeof value !== "string") return value;
      return maskMiddle(value);
    }

    case "redact_pii": {
      if (typeof value !== "string") return value;
      return value
        .replace(CN_ID_CARD_REGEX, "[REDACTED_ID]")
        .replace(CN_PHONE_REGEX, "[REDACTED_PHONE]")
        .replace(EMAIL_REGEX, "[REDACTED_EMAIL]");
    }
  }
}

function maskMiddle(input: string): string {
  if (input.length <= 2) return "*".repeat(input.length);
  if (input.length <= 4) return `${input[0]}**${input[input.length - 1]}`;
  return `${input.slice(0, 2)}***${input.slice(-2)}`;
}
