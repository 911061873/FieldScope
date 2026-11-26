export type PathSegment =
  | { type: "key"; key: string }
  | { type: "wildcard_array" }
  | { type: "wildcard_key" };

/**
 * Parses field path expressions such as:
 * - "issues[*].fields.summary"
 * - "[*].id"
 * - "users.*.email"
 * - "matrix[*][*].value"
 */
export function parseFieldPath(path: string): PathSegment[] {
  const segments: PathSegment[] = [];
  const trimmed = path.trim();
  if (!trimmed) return segments;

  const parts = trimmed.split(".");
  for (const part of parts) {
    if (!part) continue;

    // Handle patterns like "issues[*]", "[*]", "matrix[*][*]"
    const bracketRegex = /^([^[\]]*)((?:\[\*\])+)$/;
    const match = part.match(bracketRegex);
    if (match) {
      const prefix = match[1];
      const brackets = match[2];
      if (prefix) {
        if (prefix === "*") {
          segments.push({ type: "wildcard_key" });
        } else {
          segments.push({ type: "key", key: prefix });
        }
      }
      const arrayCount = brackets.length / 3;
      for (let i = 0; i < arrayCount; i++) {
        segments.push({ type: "wildcard_array" });
      }
    } else if (part === "*") {
      segments.push({ type: "wildcard_key" });
    } else {
      segments.push({ type: "key", key: part });
    }
  }

  return segments;
}

export interface PathTrieNode {
  terminal: boolean;
  keys: Map<string, PathTrieNode>;
  wildcardKey?: PathTrieNode;
  wildcardArray?: PathTrieNode;
}

export function createTrieNode(): PathTrieNode {
  return {
    terminal: false,
    keys: new Map(),
  };
}

export function buildPathTrie(paths: string[]): PathTrieNode {
  const root = createTrieNode();
  for (const path of paths) {
    const segments = parseFieldPath(path);
    if (segments.length === 0) continue;
    let current = root;
    for (const seg of segments) {
      if (seg.type === "key") {
        let next = current.keys.get(seg.key);
        if (!next) {
          next = createTrieNode();
          current.keys.set(seg.key, next);
        }
        current = next;
      } else if (seg.type === "wildcard_key") {
        if (!current.wildcardKey) {
          current.wildcardKey = createTrieNode();
        }
        current = current.wildcardKey;
      } else if (seg.type === "wildcard_array") {
        if (!current.wildcardArray) {
          current.wildcardArray = createTrieNode();
        }
        current = current.wildcardArray;
      }
    }
    current.terminal = true;
  }
  return root;
}
