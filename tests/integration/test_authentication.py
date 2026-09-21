"""
Integration tests for app.security.authentication.jwt.verify_token against
a real DevKeyProvider — the layer that turns a raw token into trusted
claims. HTTP-level attack scenarios live in tests/security/test_token_attacks.py;
these tests exercise the verification function directly with a wider set
of malformed inputs than is convenient to construct through the API.
"""
from __future__ import annotations

import time

import jwt as pyjwt
import pytest

from app.config import settings
from app.security.authentication.jwks import DevKeyProvider
from app.security.authentication.jwt import AuthenticationError, verify_token


@pytest.fixture
def key_provider():
    return DevKeyProvider(settings.dev_keys_dir)


def test_valid_token_round_trips_to_claims(token_factory, key_provider):
    token = token_factory("user-a1")
    claims = verify_token(token, settings, key_provider)
    assert claims["sub"] == "user-a1"
    assert claims["tenant_id"] == "tenant-a"
    assert claims["roles"] == ["user"]
    assert claims["scopes"] == ["vault:read", "vault:write"]


def test_scopes_as_space_delimited_string_is_normalized_to_a_list(token_factory, key_provider):
    token = token_factory("user-a1", claim_overrides={"scopes": "vault:read vault:write"})
    claims = verify_token(token, settings, key_provider)
    assert claims["scopes"] == ["vault:read", "vault:write"]


def test_expired_token_is_rejected(token_factory, key_provider):
    token = token_factory("user-a1", ttl=-10)
    with pytest.raises(AuthenticationError) as exc_info:
        verify_token(token, settings, key_provider)
    assert exc_info.value.code == "EXPIRED"


def test_wrong_issuer_is_rejected(token_factory, key_provider):
    token = token_factory("user-a1", claim_overrides={"iss": "https://malicious-issuer.example"})
    with pytest.raises(AuthenticationError) as exc_info:
        verify_token(token, settings, key_provider)
    assert exc_info.value.code == "INVALID_ISSUER"


def test_wrong_audience_is_rejected(token_factory, key_provider):
    token = token_factory("user-a1", claim_overrides={"aud": "some-other-api"})
    with pytest.raises(AuthenticationError) as exc_info:
        verify_token(token, settings, key_provider)
    assert exc_info.value.code == "INVALID_AUDIENCE"


def test_tampered_signature_is_rejected(token_factory, key_provider):
    token = token_factory("user-a1")
    header, payload, signature = token.split(".")
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered_token = f"{header}.{payload}.{tampered_signature}"
    with pytest.raises(AuthenticationError) as exc_info:
        verify_token(tampered_token, settings, key_provider)
    assert exc_info.value.code in {"INVALID_SIGNATURE", "INVALID_TOKEN"}


def test_missing_tenant_id_claim_is_rejected(dev_private_key_pem, dev_kid):
    now = int(time.time())
    claims = {
        "sub": "user-a1",
        "roles": ["user"],
        "scopes": ["vault:read"],
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + 900,
        # tenant_id deliberately omitted
    }
    token = pyjwt.encode(claims, dev_private_key_pem, algorithm="RS256", headers={"kid": dev_kid})
    key_provider = DevKeyProvider(settings.dev_keys_dir)
    with pytest.raises(AuthenticationError) as exc_info:
        verify_token(token, settings, key_provider)
    assert exc_info.value.code == "MISSING_CLAIM"


def test_disallowed_algorithm_is_rejected(dev_private_key_pem, dev_kid, key_provider):
    # HS256 signed with the RSA private key's PEM bytes as an HMAC secret.
    # Even if this "verifies" as HS256, our allowlist is RS256-only, so the
    # algorithm check must reject it before any key material is even used.
    now = int(time.time())
    claims = {
        "sub": "user-a1",
        "tenant_id": "tenant-a",
        "roles": ["user"],
        "scopes": ["vault:read"],
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + 900,
    }
    forged_token = pyjwt.encode(
        claims, "attacker-controlled-secret", algorithm="HS256", headers={"kid": dev_kid}
    )
    with pytest.raises(AuthenticationError) as exc_info:
        verify_token(forged_token, settings, key_provider)
    assert exc_info.value.code == "INVALID_ALGORITHM"


def test_unknown_kid_is_rejected(token_factory, key_provider):
    token = token_factory("user-a1", claim_overrides={})
    header_b64, payload_b64, signature_b64 = token.split(".")
    import base64
    import json

    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    header["kid"] = "not-a-real-kid"
    forged_header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    forged_token = f"{forged_header_b64}.{payload_b64}.{signature_b64}"

    with pytest.raises(AuthenticationError) as exc_info:
        verify_token(forged_token, settings, key_provider)
    assert exc_info.value.code == "UNKNOWN_KID"
