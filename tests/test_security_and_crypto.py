from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from fieldscope.core.crypto import SecretCipher
from fieldscope.core.security import (
    APP_API_KEY_PREFIX,
    USER_API_KEY_PREFIX,
    create_access_token,
    decode_access_token,
    generate_api_key,
    hash_api_key,
    hash_password,
    verify_password,
)


def test_secret_cipher_roundtrip_and_aad_protection() -> None:
    cipher = SecretCipher("super-secret-master-key")
    payload = {"client_id": "abc", "client_secret": "top-secret", "location": "header"}

    encrypted = cipher.encrypt_json(payload, aad="platform:1")
    assert encrypted.startswith("v1:")
    assert "top-secret" not in encrypted

    decrypted = cipher.decrypt_json(encrypted, aad="platform:1")
    assert decrypted == payload

    with pytest.raises(InvalidTag):
        cipher.decrypt_json(encrypted, aad="platform:2")


def test_scrypt_password_hashing() -> None:
    hashed = hash_password("MyStrongPass!2026")
    assert hashed.startswith("scrypt$")
    assert verify_password("MyStrongPass!2026", hashed) is True
    assert verify_password("WrongPassword", hashed) is False
    assert verify_password("MyStrongPass!2026", "corrupted-hash") is False


def test_jwt_and_api_key_helpers() -> None:
    secret = "jwt-test-secret-with-plenty-of-entropy-1234567890"
    token, expires_at = create_access_token("42", secret_key=secret, extra_claims={"username": "u"})
    assert expires_at is not None
    claims = decode_access_token(token, secret_key=secret)
    assert claims["sub"] == "42"
    assert claims["username"] == "u"

    usr_key, usr_prefix, usr_hash = generate_api_key(USER_API_KEY_PREFIX)
    assert usr_key.startswith(USER_API_KEY_PREFIX)
    assert usr_key.startswith(usr_prefix)
    assert hash_api_key(usr_key) == usr_hash

    app_key, app_prefix, app_hash = generate_api_key(APP_API_KEY_PREFIX)
    assert app_key.startswith(APP_API_KEY_PREFIX)
    assert app_key.startswith(app_prefix)
    assert hash_api_key(app_key) == app_hash
