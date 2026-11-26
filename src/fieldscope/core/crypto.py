from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretCipher:
    """AES-256-GCM authenticated encryption helper for storing sensitive platform credentials."""

    VERSION = "v1"
    NONCE_SIZE = 12

    def __init__(self, key_material: str | bytes) -> None:
        raw = key_material.encode("utf-8") if isinstance(key_material, str) else key_material
        if not raw:
            raise ValueError("encryption key material must not be empty")
        # Derive a fixed 32-byte AES-256 key deterministically from arbitrary passphrase/key bytes.
        self._key = hashlib.sha256(raw).digest()
        self._aesgcm = AESGCM(self._key)

    def encrypt_str(self, plaintext: str, aad: str | None = None) -> str:
        nonce = os.urandom(self.NONCE_SIZE)
        aad_bytes = aad.encode("utf-8") if aad else None
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad_bytes)
        nonce_b64 = base64.urlsafe_b64encode(nonce).decode("ascii")
        ct_b64 = base64.urlsafe_b64encode(ciphertext).decode("ascii")
        return f"{self.VERSION}:{nonce_b64}:{ct_b64}"

    def decrypt_str(self, token: str, aad: str | None = None) -> str:
        parts = token.split(":")
        if len(parts) != 3 or parts[0] != self.VERSION:
            raise ValueError("Invalid encrypted secret envelope format")
        nonce = base64.urlsafe_b64decode(parts[1].encode("ascii"))
        ciphertext = base64.urlsafe_b64decode(parts[2].encode("ascii"))
        aad_bytes = aad.encode("utf-8") if aad else None
        plaintext = self._aesgcm.decrypt(nonce, ciphertext, aad_bytes)
        return plaintext.decode("utf-8")

    def encrypt_json(self, payload: dict[str, Any], aad: str | None = None) -> str:
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        return self.encrypt_str(serialized, aad=aad)

    def decrypt_json(self, token: str, aad: str | None = None) -> dict[str, Any]:
        serialized = self.decrypt_str(token, aad=aad)
        data = json.loads(serialized)
        if not isinstance(data, dict):
            raise ValueError("Decrypted JSON secret must be an object")
        return data
