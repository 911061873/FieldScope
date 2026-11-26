export type TokenType =
  | "NUMBER"
  | "STRING"
  | "IDENT"
  | "BOOL"
  | "NULL"
  | "OP"
  | "LPAREN"
  | "RPAREN"
  | "LBRACKET"
  | "RBRACKET"
  | "COMMA"
  | "EOF";

interface Token {
  type: TokenType;
  value: string;
}

const KEYWORDS = new Set(["in", "contains", "startsWith", "and", "or", "not"]);

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < input.length) {
    const ch = input[i];

    if (/\s/.test(ch)) {
      i++;
      continue;
    }

    // Two-char operators
    const two = input.slice(i, i + 2);
    if (["==", "!=", "<=", ">=", "&&", "||"].includes(two)) {
      tokens.push({ type: "OP", value: two });
      i += 2;
      continue;
    }

    // Single-char operators & delimiters
    if (["<", ">", "!"].includes(ch)) {
      tokens.push({ type: "OP", value: ch });
      i++;
      continue;
    }
    if (ch === "(") {
      tokens.push({ type: "LPAREN", value: ch });
      i++;
      continue;
    }
    if (ch === ")") {
      tokens.push({ type: "RPAREN", value: ch });
      i++;
      continue;
    }
    if (ch === "[") {
      tokens.push({ type: "LBRACKET", value: ch });
      i++;
      continue;
    }
    if (ch === "]") {
      tokens.push({ type: "RBRACKET", value: ch });
      i++;
      continue;
    }
    if (ch === ",") {
      tokens.push({ type: "COMMA", value: ch });
      i++;
      continue;
    }

    // String literals
    if (ch === '"' || ch === "'") {
      const quote = ch;
      i++;
      let str = "";
      while (i < input.length && input[i] !== quote) {
        if (input[i] === "\\" && i + 1 < input.length) {
          i++;
          str += input[i];
        } else {
          str += input[i];
        }
        i++;
      }
      if (i >= input.length) {
        throw new Error(`Unterminated string literal in expression: ${input}`);
      }
      i++; // skip closing quote
      tokens.push({ type: "STRING", value: str });
      continue;
    }

    // Number literals (including negative numbers when preceded by operator/start)
    if (
      /\d/.test(ch) ||
      (ch === "-" &&
        /\d/.test(input[i + 1] ?? "") &&
        (tokens.length === 0 ||
          ["OP", "LPAREN", "LBRACKET", "COMMA"].includes(
            tokens[tokens.length - 1].type
          )))
    ) {
      let num = ch;
      i++;
      while (i < input.length && /[\d.]/.test(input[i])) {
        num += input[i];
        i++;
      }
      tokens.push({ type: "NUMBER", value: num });
      continue;
    }

    // Identifiers / paths (e.g. query.maxResults, principal.attributes.dept)
    if (/[a-zA-Z_$]/.test(ch)) {
      let ident = ch;
      i++;
      while (i < input.length && /[a-zA-Z0-9_$.-]/.test(input[i])) {
        ident += input[i];
        i++;
      }
      if (ident === "true" || ident === "false") {
        tokens.push({ type: "BOOL", value: ident });
      } else if (ident === "null") {
        tokens.push({ type: "NULL", value: ident });
      } else if (KEYWORDS.has(ident)) {
        tokens.push({ type: "OP", value: ident });
      } else {
        tokens.push({ type: "IDENT", value: ident });
      }
      continue;
    }

    throw new Error(`Unexpected character '${ch}' in expression: ${input}`);
  }

  tokens.push({ type: "EOF", value: "" });
  return tokens;
}

export function resolvePath(
  context: Record<string, unknown>,
  path: string
): unknown {
  const parts = path.split(".");
  let current: unknown = context;
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function toNumberIfNumeric(val: unknown): number | null {
  if (typeof val === "number" && !Number.isNaN(val)) return val;
  if (typeof val === "string" && val.trim() !== "") {
    const n = Number(val);
    if (!Number.isNaN(n)) return n;
  }
  return null;
}

function compareValues(op: string, left: unknown, right: unknown): boolean {
  switch (op) {
    case "==": {
      if (left === right) return true;
      const ln = toNumberIfNumeric(left);
      const rn = toNumberIfNumeric(right);
      if (ln !== null && rn !== null) return ln === rn;
      return false;
    }
    case "!=":
      return !compareValues("==", left, right);
    case "<":
    case "<=":
    case ">":
    case ">=": {
      const ln = toNumberIfNumeric(left);
      const rn = toNumberIfNumeric(right);
      if (ln === null || rn === null) return false;
      if (op === "<") return ln < rn;
      if (op === "<=") return ln <= rn;
      if (op === ">") return ln > rn;
      return ln >= rn;
    }
    case "in": {
      if (Array.isArray(right)) {
        return right.some((item) => compareValues("==", left, item));
      }
      if (typeof right === "string" && typeof left === "string") {
        return right.includes(left);
      }
      return false;
    }
    case "contains": {
      if (Array.isArray(left)) {
        return left.some((item) => compareValues("==", item, right));
      }
      if (typeof left === "string" && typeof right === "string") {
        return left.includes(right);
      }
      return false;
    }
    case "startsWith": {
      return (
        typeof left === "string" &&
        typeof right === "string" &&
        left.startsWith(right)
      );
    }
    default:
      throw new Error(`Unsupported operator: ${op}`);
  }
}

class Parser {
  private pos = 0;
  private readonly tokens: Token[];
  private readonly context: Record<string, unknown>;

  constructor(tokens: Token[], context: Record<string, unknown>) {
    this.tokens = tokens;
    this.context = context;
  }

  private peek(): Token {
    return this.tokens[this.pos];
  }

  private consume(): Token {
    return this.tokens[this.pos++];
  }

  parse(): unknown {
    const result = this.parseOr();
    if (this.peek().type !== "EOF") {
      throw new Error(`Unexpected token '${this.peek().value}'`);
    }
    return result;
  }

  private parseOr(): unknown {
    let left = this.parseAnd();
    while (
      this.peek().type === "OP" &&
      (this.peek().value === "||" || this.peek().value === "or")
    ) {
      this.consume();
      const right = this.parseAnd();
      left = Boolean(left) || Boolean(right);
    }
    return left;
  }

  private parseAnd(): unknown {
    let left = this.parseUnary();
    while (
      this.peek().type === "OP" &&
      (this.peek().value === "&&" || this.peek().value === "and")
    ) {
      this.consume();
      const right = this.parseUnary();
      left = Boolean(left) && Boolean(right);
    }
    return left;
  }

  private parseUnary(): unknown {
    if (
      this.peek().type === "OP" &&
      (this.peek().value === "!" || this.peek().value === "not")
    ) {
      this.consume();
      return !Boolean(this.parseUnary());
    }
    return this.parseComparison();
  }

  private parseComparison(): unknown {
    const left = this.parsePrimary();
    const next = this.peek();
    if (
      next.type === "OP" &&
      [
        "==",
        "!=",
        "<",
        "<=",
        ">",
        ">=",
        "in",
        "contains",
        "startsWith",
      ].includes(next.value)
    ) {
      const op = this.consume().value;
      const right = this.parsePrimary();
      return compareValues(op, left, right);
    }
    return left;
  }

  private parsePrimary(): unknown {
    const tok = this.peek();

    if (tok.type === "LPAREN") {
      this.consume();
      const val = this.parseOr();
      if (this.peek().type !== "RPAREN") {
        throw new Error("Expected closing ')'");
      }
      this.consume();
      return val;
    }

    if (tok.type === "LBRACKET") {
      this.consume();
      const items: unknown[] = [];
      if (this.peek().type !== "RBRACKET") {
        items.push(this.parseOr());
        while (this.peek().type === "COMMA") {
          this.consume();
          items.push(this.parseOr());
        }
      }
      if (this.peek().type !== "RBRACKET") {
        throw new Error("Expected closing ']'");
      }
      this.consume();
      return items;
    }

    if (tok.type === "NUMBER") {
      this.consume();
      return Number(tok.value);
    }
    if (tok.type === "STRING") {
      this.consume();
      return tok.value;
    }
    if (tok.type === "BOOL") {
      this.consume();
      return tok.value === "true";
    }
    if (tok.type === "NULL") {
      this.consume();
      return null;
    }
    if (tok.type === "IDENT") {
      this.consume();
      return resolvePath(this.context, tok.value);
    }

    throw new Error(`Unexpected token '${tok.value}' (${tok.type})`);
  }
}

/**
 * Safely evaluates boolean policy expressions without using eval() or Function().
 */
export function evaluateExpression(
  expr: string,
  context: Record<string, unknown>
): boolean {
  const tokens = tokenize(expr);
  const parser = new Parser(tokens, context);
  return Boolean(parser.parse());
}
