"""
Black-box token attacks against the live HTTP API. These mirror
tests/integration/test_authentication.py but at the boundary an actual
attacker controls: the raw Authorization header, with no knowledge of
internal function names.
"""
from __future__ import annotations

import base64
import json
import time

import jwt as pyjwt
import pytest

from app.config import settings


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _craft_raw_token(header: dict, payload: dict, signature: bytes = b"forged") -> str:
    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    signature_b64 = _b64url(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _valid_claims(**overrides) -> dict:
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
    claims.update(overrides)
    return claims


@pytest.mark.parametrize("bad_header", [None, "", "abc.def.ghi", "Bearer", "Basic dXNlcjpwYXNz"])
def test_missing_or_malformed_authorization_header_is_401(client, bad_header):
    headers = {} if bad_header is None else {"Authorization": bad_header}
    response = client.get("/api/v1/vault/vault-a1", headers=headers)
    assert response.status_code == 401


def test_expired_token_is_401(client, auth_header):
    headers = auth_header("user-a1", ttl=-60)
    response = client.get("/api/v1/vault/vault-a1", headers=headers)
    assert response.status_code == 401


def test_tampered_payload_is_401(client, auth_header):
    token = auth_header("user-a1")["Authorization"].removeprefix("Bearer ")
    header_b64, payload_b64, signature_b64 = token.split(".")

    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    payload["tenant_id"] = "tenant-b"  # attacker tries to forge their tenant
    tampered_payload_b64 = _b64url(json.dumps(payload).encode())

    forged_token = f"{header_b64}.{tampered_payload_b64}.{signature_b64}"
    response = client.get("/api/v1/vault/vault-a1", headers={"Authorization": f"Bearer {forged_token}"})
    assert response.status_code == 401  # signature no longer matches the tampered payload


def test_alg_none_attack_is_rejected(client):
    header = {"alg": "none", "typ": "JWT", "kid": "irrelevant"}
    token = _craft_raw_token(header, _valid_claims(), signature=b"")
    response = client.get("/api/v1/vault/vault-a1", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_hs256_key_confusion_attack_is_rejected(client, dev_private_key_pem):
    # Attacker guesses (or obtains) the RSA public key and tries to use it
    # as an HMAC secret to self-sign an HS256 token. Our algorithm
    # allowlist (RS256 only) must reject this before any key is even used.
    forged = pyjwt.encode(
        _valid_claims(),
        key="some-guessed-or-public-value",
        algorithm="HS256",
        headers={"kid": "irrelevant"},
    )
    response = client.get("/api/v1/vault/vault-a1", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_missing_kid_is_rejected(client):
    header = {"alg": "RS256", "typ": "JWT"}  # no kid
    token = _craft_raw_token(header, _valid_claims())
    response = client.get("/api/v1/vault/vault-a1", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_unknown_kid_is_rejected(client):
    header = {"alg": "RS256", "typ": "JWT", "kid": "not-a-real-key-id"}
    token = _craft_raw_token(header, _valid_claims())
    response = client.get("/api/v1/vault/vault-a1", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_missing_required_claims_is_rejected(client, dev_private_key_pem, dev_kid):
    claims = _valid_claims()
    del claims["exp"]
    token = pyjwt.encode(claims, dev_private_key_pem, algorithm="RS256", headers={"kid": dev_kid})
    response = client.get("/api/v1/vault/vault-a1", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_denial_response_does_not_leak_the_specific_failure_reason(client, auth_header):
    # The server-side reason CODE (EXPIRED, INVALID_SIGNATURE, INVALID_AUDIENCE,
    # ...) is for the audit trail, not the wire — otherwise an attacker could
    # use the response to fuzz their way toward a valid token. The response
    # is allowed to say something generic like "invalid or expired token";
    # it must not echo back the machine-readable code from AuthenticationError.
    headers = auth_header("user-a1", ttl=-60)
    response = client.get("/api/v1/vault/vault-a1", headers=headers)
    assert response.status_code == 401
    leaking_codes = [
        "EXPIRED", "INVALID_SIGNATURE", "INVALID_AUDIENCE", "INVALID_ISSUER",
        "INVALID_ALGORITHM", "MISSING_CLAIM", "MISSING_KID", "UNKNOWN_KID",
        "MALFORMED_TOKEN", "INVALID_CLAIM_TYPE", "INVALID_TOKEN",
    ]
    for code in leaking_codes:
        assert code not in response.text
