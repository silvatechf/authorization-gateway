"""
Token verification.

Every claim the authorization layer relies on (sub, tenant_id, roles,
scopes) is only trustworthy if the signature, algorithm, issuer, audience
and time-based claims have already been validated here. This module is the
single choke point for that validation — nothing downstream re-implements
it.
"""
from __future__ import annotations

import jwt as pyjwt

from app.config import Settings
from app.security.authentication.jwks import KeyResolutionError


class AuthenticationError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


REQUIRED_CLAIMS = ["exp", "iat", "nbf", "sub", "aud", "iss"]


def verify_token(token: str, settings: Settings, key_provider) -> dict:
    # 1. Inspect the header WITHOUT trusting it, to pick the algorithm and
    #    kid used to look up a key. The algorithm from the header is never
    #    passed to jwt.decode's `algorithms` allowlist directly — decode is
    #    always called with our own server-side allowlist, so a token
    #    cannot force an unexpected algorithm even if the header lies.
    try:
        unverified_header = pyjwt.get_unverified_header(token)
    except pyjwt.exceptions.DecodeError as exc:
        raise AuthenticationError("MALFORMED_TOKEN", "Token could not be parsed") from exc

    header_alg = unverified_header.get("alg")
    if header_alg not in settings.jwt_algorithms:
        raise AuthenticationError(
            "INVALID_ALGORITHM",
            f"Algorithm '{header_alg}' is not in the trusted allowlist",
        )

    unverified_kid = unverified_header.get("kid")
    if not unverified_kid:
        raise AuthenticationError("MISSING_KID", "Token header is missing 'kid'")

    try:
        signing_key = key_provider.resolve_key(token, unverified_kid)
    except KeyResolutionError as exc:
        raise AuthenticationError(exc.code, exc.message) from exc

    try:
        claims = pyjwt.decode(
            token,
            key=signing_key,
            algorithms=settings.jwt_algorithms,  # server-controlled allowlist only
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={
                "require": REQUIRED_CLAIMS,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_signature": True,
            },
        )
    except pyjwt.exceptions.ExpiredSignatureError as exc:
        raise AuthenticationError("EXPIRED", "Token has expired") from exc
    except pyjwt.exceptions.InvalidAudienceError as exc:
        raise AuthenticationError("INVALID_AUDIENCE", "Token audience is not accepted") from exc
    except pyjwt.exceptions.InvalidIssuerError as exc:
        raise AuthenticationError("INVALID_ISSUER", "Token issuer is not trusted") from exc
    except pyjwt.exceptions.InvalidSignatureError as exc:
        raise AuthenticationError("INVALID_SIGNATURE", "Token signature verification failed") from exc
    except pyjwt.exceptions.MissingRequiredClaimError as exc:
        raise AuthenticationError("MISSING_CLAIM", str(exc)) from exc
    except pyjwt.exceptions.InvalidTokenError as exc:
        raise AuthenticationError("INVALID_TOKEN", str(exc)) from exc

    tenant_id = claims.get("tenant_id")
    if not tenant_id or not isinstance(tenant_id, str):
        raise AuthenticationError("MISSING_CLAIM", "Token is missing a valid 'tenant_id' claim")

    roles = claims.get("roles", [])
    if not isinstance(roles, list):
        raise AuthenticationError("INVALID_CLAIM_TYPE", "'roles' claim must be a list")

    scopes = claims.get("scopes", [])
    if isinstance(scopes, str):
        scopes = scopes.split()
    if not isinstance(scopes, list):
        raise AuthenticationError(
            "INVALID_CLAIM_TYPE", "'scopes' claim must be a list or space-delimited string"
        )

    claims["roles"] = roles
    claims["scopes"] = scopes
    return claims
