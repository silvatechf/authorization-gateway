"""
In-memory seed data.

This stands in for a real database so the gateway is runnable and
demonstrable without external infrastructure. Two tenants, each with an
admin, a regular user and one vault resource, is enough to exercise every
row of the authorization matrix (ownership, role/scope, and cross-tenant
denial) documented in the README.
"""
from __future__ import annotations

import copy
import threading

from app.models import User, VaultResource


def _seed_users() -> dict[str, User]:
    return {
        "user-a1": User(
            id="user-a1", tenant_id="tenant-a", roles=["user"], scopes=["vault:read", "vault:write"],
        ),
        "user-a2": User(id="user-a2", tenant_id="tenant-a", roles=["user"], scopes=["vault:read"]),
        "admin-a": User(id="admin-a", tenant_id="tenant-a", roles=["admin"], scopes=[
            "vault:read", "vault:write", "vault:delete", "vault:share", "vault:admin",
            "admin:read", "admin:write",
        ]),
        "user-b1": User(
            id="user-b1", tenant_id="tenant-b", roles=["user"], scopes=["vault:read", "vault:write"],
        ),
    }


def _seed_resources() -> dict[str, VaultResource]:
    return {
        "vault-a1": VaultResource(
            id="vault-a1", tenant_id="tenant-a", owner_id="user-a1",
            name="tenant-a shared secret", secret_value="s3cr3t-a1",  # nosec B106
        ),
        "vault-b1": VaultResource(
            id="vault-b1", tenant_id="tenant-b", owner_id="user-b1",
            name="tenant-b shared secret", secret_value="s3cr3t-b1",  # nosec B106
        ),
    }


_users: dict[str, User] = _seed_users()
_resources: dict[str, VaultResource] = _seed_resources()

_lock = threading.Lock()
_next_id = 2


def reset() -> None:
    """
    Restore the store to its original seed state.

    Test-only utility: the security/integration test suite mutates this
    in-memory store (creating and deleting resources), so each test needs
    a clean, deterministic starting point rather than leaking state into
    the next test. Not used by the running application itself.
    """
    global _users, _resources, _next_id
    with _lock:
        _users = copy.deepcopy(_seed_users())
        _resources = copy.deepcopy(_seed_resources())
        _next_id = 2


def get_user(user_id: str) -> User | None:
    return _users.get(user_id)


def get_resource(resource_id: str) -> VaultResource | None:
    with _lock:
        return _resources.get(resource_id)


def update_resource_value(resource_id: str, new_value: str) -> VaultResource | None:
    with _lock:
        resource = _resources.get(resource_id)
        if resource is None:
            return None
        resource.secret_value = new_value
        return resource


def delete_resource(resource_id: str) -> bool:
    with _lock:
        return _resources.pop(resource_id, None) is not None


def create_resource(tenant_id: str, owner_id: str, name: str, secret_value: str) -> VaultResource:
    global _next_id
    with _lock:
        resource_id = f"vault-{_next_id}"
        _next_id += 1
        resource = VaultResource(
            id=resource_id, tenant_id=tenant_id, owner_id=owner_id,
            name=name, secret_value=secret_value,
        )
        _resources[resource_id] = resource
        return resource
