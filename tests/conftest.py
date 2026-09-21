"""
Shared test fixtures.

IMPORTANT: environment variables that drive app.config.Settings are read
at import time (Settings' dataclass field defaults call os.getenv() when
the class body executes). They must be set here, before anything imports
app.config / app.main, which is why this block sits above every other
import in this file.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time

_TEST_KEYS_DIR = tempfile.mkdtemp(prefix="authz-gateway-test-keys-")
os.environ["JWKS_MODE"] = "dev"
os.environ["DEV_KEYS_DIR"] = _TEST_KEYS_DIR
os.environ["JWT_ISSUER"] = "https://auth.example.local"
os.environ["JWT_AUDIENCE"] = "authorization-gateway"
os.environ["JWT_ALGORITHMS"] = "RS256"

import jwt as pyjwt  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.data import store  # noqa: E402
from app.main import app  # noqa: E402
from app.security.authentication import keys as dev_keys  # noqa: E402

dev_keys.ensure_dev_keypair(settings.dev_keys_dir)


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TEST_KEYS_DIR, ignore_errors=True)


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_store():
    """Every test starts from the same clean seed data (see app/data/store.py)."""
    store.reset()
    yield
    store.reset()


def issue_token(user_id: str, ttl: int = 900, claim_overrides: dict | None = None) -> str:
    """Mint a valid, correctly-signed demo JWT for a seeded user."""
    user = store.get_user(user_id)
    assert user is not None, f"no seeded user '{user_id}'"

    now = int(time.time())
    claims = {
        "sub": user.id,
        "tenant_id": user.tenant_id,
        "roles": user.roles,
        "scopes": user.scopes,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    if claim_overrides:
        claims.update(claim_overrides)

    private_pem = dev_keys.load_private_key_pem(settings.dev_keys_dir)
    kid = dev_keys.load_kid(settings.dev_keys_dir)
    return pyjwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def token_factory():
    return issue_token


@pytest.fixture
def auth_header(token_factory):
    def _make(user_id: str, **kwargs) -> dict:
        token = token_factory(user_id, **kwargs)
        return {"Authorization": f"Bearer {token}"}

    return _make


@pytest.fixture
def dev_kid() -> str:
    return dev_keys.load_kid(settings.dev_keys_dir)


@pytest.fixture
def dev_private_key_pem() -> bytes:
    return dev_keys.load_private_key_pem(settings.dev_keys_dir)
