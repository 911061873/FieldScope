import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const VERSION = "v1";

/**
 * AES-256-GCM authenticated encryption for credentials at rest.
 * Ciphertext format: v1:<iv_base64>:<authTag_base64>:<ciphertext_base64>
 */
export class CredentialCipher {
  private readonly key: Buffer;

  constructor(masterKey: string | Buffer) {
    if (Buffer.isBuffer(masterKey)) {
      this.key =
        masterKey.length === 32
          ? masterKey
          : createHash("sha256").update(masterKey).digest();
    } else if (/^[0-9a-fA-F]{64}$/.test(masterKey)) {
      this.key = Buffer.from(masterKey, "hex");
    } else {
      this.key = createHash("sha256").update(masterKey, "utf-8").digest();
    }
  }

  encrypt(plaintext: string): string {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, "utf-8"),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    return [
      VERSION,
      iv.toString("base64"),
      authTag.toString("base64"),
      encrypted.toString("base64"),
    ].join(":");
  }

  decrypt(payload: string): string {
    const parts = payload.split(":");
    if (parts.length !== 4 || parts[0] !== VERSION) {
      throw new Error("Unsupported or malformed encrypted credential payload");
    }
    const [, ivB64, tagB64, dataB64] = parts;
    const iv = Buffer.from(ivB64, "base64");
    const authTag = Buffer.from(tagB64, "base64");
    const data = Buffer.from(dataB64, "base64");

    const decipher = createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    return decrypted.toString("utf-8");
  }
}
