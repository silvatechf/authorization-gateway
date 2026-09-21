"""
FastAPI dependencies shared by every route: correlation id, authentication
(-> IdentityContext) and access to the singleton PolicyEngine / key
provider set up at startup.
"""
from __future__ import annotations

import uuid

from fastapi import Header, HTTPException, Request, status

from app.config import settings
from app.security.authentication.jwks import DevKeyProvider, ProductionJWKSProvider
from app.security.authentication.jwt import AuthenticationError, verify_token
from app.security.authorization.context import IdentityContext
from app.security.authorization.engine import PolicyEngine

policy_engine = PolicyEngine()

# Populated at startup in main.py, based on JWKS_MODE.
key_provider: DevKeyProvider | ProductionJWKSProvider | None = None


def get_correlation_id(request: Request) -> str:
    header_name = settings.correlation_id_header
    incoming = request.headers.get(header_name)
    correlation_id = incoming or str(uuid.uuid4())
    request.state.correlation_id = correlation_id
    return correlation_id


def get_identity(
    request: Request,
    authorization: str | None = Header(default=None),
) -> IdentityContext:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.removeprefix("Bearer ").strip()

    if key_provider is None:
        # Fails closed: if startup did not wire a key provider, no token
        # can ever be verified.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Authentication is not ready"
        )

    try:
        claims = verify_token(token, settings, key_provider)
    except AuthenticationError as exc:
        # The client gets a generic message; the specific reason code is
        # only surfaced in server-side logs / audit trail, not over the
        # wire, to avoid handing attackers a token-fuzzing oracle.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    identity = IdentityContext(
        user_id=claims["sub"],
        tenant_id=claims["tenant_id"],
        roles=claims["roles"],
        scopes=claims["scopes"],
    )
    request.state.identity = identity
    return identity
