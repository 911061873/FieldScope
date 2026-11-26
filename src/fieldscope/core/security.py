from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

USER_API_KEY_PREFIX = "fs_usr_"
APP_API_KEY_PREFIX = "fs_app_"

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


def hash_password(password: str) -> str:
    """Hash a password using stdlib scrypt with a random 16-byte salt."""
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
    hash_b64 = base64.urlsafe_b64encode(derived).decode("ascii")
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt_b64}${hash_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored scrypt hash in constant time."""
    parts = stored_hash.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return False
    try:
        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
        salt = base64.urlsafe_b64decode(parts[4].encode("ascii"))
        expected = base64.urlsafe_b64decode(parts[5].encode("ascii"))
    except (ValueError, TypeError):
        return False

    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=len(expected),
    )
    return hmac.compare_digest(derived, expected)


def create_access_token(
    subject: str,
    secret_key: str,
    algorithm: str = "HS256",
    expires_minutes: int = 720,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, datetime]:
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=expires_minutes)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token, expires_at


def decode_access_token(
    token: str,
    secret_key: str,
    algorithm: str = "HS256",
) -> dict[str, Any]:
    return jwt.decode(token, secret_key, algorithms=[algorithm])


def hash_api_key(plain_key: str) -> str:
    """Hash a high-entropy API key with SHA-256 for indexed DB lookup."""
    return hashlib.sha256(plain_key.encode("utf-8")).hexdigest()


def generate_api_key(prefix: str) -> tuple[str, str, str]:
    """Generate a prefixed API key returning (plain_key, display_prefix, sha256_hash)."""
    token_body = secrets.token_urlsafe(32)
    plain_key = f"{prefix}{token_body}"
    display_prefix = plain_key[: len(prefix) + 8]
    return plain_key, display_prefix, hash_api_key(plain_key)
