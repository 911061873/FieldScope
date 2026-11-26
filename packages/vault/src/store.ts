import { DatabaseSync } from "node:sqlite";
import { CredentialCipher } from "./crypto.ts";

export interface StoredOAuthToken {
  accessToken: string;
  refreshToken?: string;
  /** Unix timestamp in milliseconds when accessToken expires */
  expiresAt?: number;
  tokenType?: string;
  scope?: string;
}

export interface CredentialStore {
  getOAuthToken(
    userId: string,
    connectorId: string
  ): Promise<StoredOAuthToken | null>;
  setOAuthToken(
    userId: string,
    connectorId: string,
    token: StoredOAuthToken
  ): Promise<void>;
  deleteOAuthToken(userId: string, connectorId: string): Promise<void>;
  close?(): void;
}

/**
 * In-memory encrypted credential store (tokens are encrypted with AES-256-GCM even in memory).
 */
export class InMemoryCredentialStore implements CredentialStore {
  private readonly cipher: CredentialCipher;
  private readonly records = new Map<string, string>();

  constructor(cipher: CredentialCipher) {
    this.cipher = cipher;
  }

  private key(userId: string, connectorId: string): string {
    return `${userId}::${connectorId}`;
  }

  async getOAuthToken(
    userId: string,
    connectorId: string
  ): Promise<StoredOAuthToken | null> {
    const encrypted = this.records.get(this.key(userId, connectorId));
    if (!encrypted) return null;
    const raw = this.cipher.decrypt(encrypted);
    return JSON.parse(raw) as StoredOAuthToken;
  }

  async setOAuthToken(
    userId: string,
    connectorId: string,
    token: StoredOAuthToken
  ): Promise<void> {
    const encrypted = this.cipher.encrypt(JSON.stringify(token));
    this.records.set(this.key(userId, connectorId), encrypted);
  }

  async deleteOAuthToken(userId: string, connectorId: string): Promise<void> {
    this.records.delete(this.key(userId, connectorId));
  }
}

/**
 * Persistent SQLite credential store built on Node 22 native node:sqlite.
 * All token payloads are encrypted at rest with AES-256-GCM.
 */
export class SqliteCredentialStore implements CredentialStore {
  private readonly db: DatabaseSync;
  private readonly cipher: CredentialCipher;

  constructor(dbPath: string, cipher: CredentialCipher) {
    this.cipher = cipher;
    this.db = new DatabaseSync(dbPath);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS oauth_tokens (
        user_id TEXT NOT NULL,
        connector_id TEXT NOT NULL,
        encrypted_payload TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, connector_id)
      )
    `);
  }

  async getOAuthToken(
    userId: string,
    connectorId: string
  ): Promise<StoredOAuthToken | null> {
    const stmt = this.db.prepare(
      "SELECT encrypted_payload FROM oauth_tokens WHERE user_id = ? AND connector_id = ?"
    );
    const row = stmt.get(userId, connectorId) as
      | { encrypted_payload: string }
      | undefined;
    if (!row) return null;
    const raw = this.cipher.decrypt(row.encrypted_payload);
    return JSON.parse(raw) as StoredOAuthToken;
  }

  async setOAuthToken(
    userId: string,
    connectorId: string,
    token: StoredOAuthToken
  ): Promise<void> {
    const encrypted = this.cipher.encrypt(JSON.stringify(token));
    const stmt = this.db.prepare(`
      INSERT INTO oauth_tokens (user_id, connector_id, encrypted_payload, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id, connector_id)
      DO UPDATE SET encrypted_payload = excluded.encrypted_payload, updated_at = excluded.updated_at
    `);
    stmt.run(userId, connectorId, encrypted, Date.now());
  }

  async deleteOAuthToken(userId: string, connectorId: string): Promise<void> {
    const stmt = this.db.prepare(
      "DELETE FROM oauth_tokens WHERE user_id = ? AND connector_id = ?"
    );
    stmt.run(userId, connectorId);
  }

  close(): void {
    this.db.close();
  }
}
