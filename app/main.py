"""
Application entrypoint.

Startup responsibilities (see `lifespan` below):
  1. Validate configuration (fail fast if JWKS_MODE=production without a
     JWKS_URL, or if an insecure algorithm is allowlisted).
  2. Wire the correct key provider (dev keypair vs production JWKS
     client) into app.api.deps.key_provider.
  3. In dev mode only, expose /.well-known/jwks.json so PyJWKClient-style
     consumption can be exercised locally.

Every request gets a correlation id (generated or forwarded) attached to
the response headers, so a caller can hand you one id and you can trace
the whole authorization decision through the audit log.
"""
from __future__ import annotations

import logging
import sys
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app.api import admin, deps, vault
from app.config import settings
from app.security.authentication import keys as dev_keys
from app.security.authentication.jwks import DevKeyProvider, ProductionJWKSProvider

logging.basicConfig(level=settings.log_level, stream=sys.stdout, format="%(message)s")
logger = logging.getLogger("gateway")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    problems = settings.validate_for_startup()
    if problems:
        for problem in problems:
            logger.error("STARTUP CONFIG ERROR: %s", problem)
        raise RuntimeError(
            "Refusing to start with invalid security configuration: " + "; ".join(problems)
        )

    if settings.jwks_mode == "dev":
        dev_keys.ensure_dev_keypair(settings.dev_keys_dir)
        deps.key_provider = DevKeyProvider(settings.dev_keys_dir)
        logger.warning(
            "JWKS_MODE=dev — using a locally generated, self-signed keypair. "
            "This is NOT suitable for production."
        )
    else:
        deps.key_provider = ProductionJWKSProvider(
            jwks_url=settings.jwks_url,
            cache_ttl_seconds=settings.jwks_cache_ttl_seconds,
            lru_max_keys=settings.jwks_lru_max_keys,
            timeout_seconds=settings.jwks_timeout_seconds,
        )
        logger.info("JWKS_MODE=production — signing keys resolved from %s", settings.jwks_url)

    yield

    deps.key_provider = None


app = FastAPI(
    title="Authorization Gateway",
    description=(
        "Zero-trust authorization gateway: JWT/JWKS authentication, a "
        "declarative policy engine (ownership + RBAC + scopes), tenant "
        "isolation and structured audit logging."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(vault.router)
app.include_router(admin.router)


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    correlation_id = request.headers.get(settings.correlation_id_header)
    if not correlation_id:
        correlation_id = str(uuid.uuid4())
    request.state.correlation_id = correlation_id
    response: Response = await call_next(request)
    response.headers[settings.correlation_id_header] = correlation_id
    return response


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/.well-known/jwks.json")
def jwks():
    if settings.jwks_mode != "dev":
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    return dev_keys.build_jwks(settings.dev_keys_dir)
