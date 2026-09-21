"""
PolicyEngine.evaluate() in isolation — no HTTP, no JWT. These tests pin
down the decision logic itself: the thing every other test layer builds
on top of.
"""
from __future__ import annotations

from app.security.authorization.context import IdentityContext, ResourceContext
from app.security.authorization.engine import PolicyEngine

engine = PolicyEngine()


def _identity(user_id="user-a1", tenant_id="tenant-a", roles=None, scopes=None):
    return IdentityContext(user_id=user_id, tenant_id=tenant_id, roles=roles or [], scopes=scopes or [])


def _resource(resource_id="vault-a1", tenant_id="tenant-a", owner_id="user-a1", resource_type="vault"):
    return ResourceContext(
        resource_id=resource_id, resource_type=resource_type, tenant_id=tenant_id, owner_id=owner_id,
    )


def test_unknown_action_denies_fail_closed():
    decision = engine.evaluate(subject=_identity(), action="vault.teleport", resource=_resource())
    assert decision.allowed is False
    assert decision.reason == "UNKNOWN_ACTION"


def test_owner_allowed_action_grants_owner_access():
    identity = _identity(user_id="user-a1", roles=[], scopes=[])
    resource = _resource(owner_id="user-a1")
    decision = engine.evaluate(subject=identity, action="vault.read", resource=resource)
    assert decision.allowed is True
    assert decision.reason == "OWNER"


def test_owner_without_role_or_scope_is_denied_for_non_owner_action():
    # vault.delete has owner_allowed=False: being the owner is not enough.
    identity = _identity(user_id="user-a1", roles=[], scopes=[])
    resource = _resource(owner_id="user-a1")
    decision = engine.evaluate(subject=identity, action="vault.delete", resource=resource)
    assert decision.allowed is False
    assert decision.reason == "INSUFFICIENT_ROLE_OR_SCOPE"


def test_role_and_scope_grants_access_to_non_owner():
    identity = _identity(user_id="admin-a", roles=["admin"], scopes=["vault:read"])
    resource = _resource(owner_id="user-a1")
    decision = engine.evaluate(subject=identity, action="vault.read", resource=resource)
    assert decision.allowed is True
    assert decision.reason == "ROLE_AND_SCOPE"


def test_role_without_required_scope_is_denied():
    identity = _identity(user_id="admin-a", roles=["admin"], scopes=[])  # missing vault:read
    resource = _resource(owner_id="user-a1")
    decision = engine.evaluate(subject=identity, action="vault.read", resource=resource)
    assert decision.allowed is False
    assert decision.reason == "INSUFFICIENT_ROLE_OR_SCOPE"


def test_scope_without_required_role_is_denied():
    identity = _identity(user_id="user-a2", roles=["user"], scopes=["vault:read"])  # role not in ["admin"]
    resource = _resource(owner_id="user-a1")
    decision = engine.evaluate(subject=identity, action="vault.read", resource=resource)
    assert decision.allowed is False
    assert decision.reason == "INSUFFICIENT_ROLE_OR_SCOPE"


def test_cross_tenant_denies_before_ownership_is_even_considered():
    # Same user id as owner, but resource now belongs to a different tenant:
    # tenant check must fire first, regardless of ownership match.
    identity = _identity(user_id="user-a1", tenant_id="tenant-a")
    resource = _resource(tenant_id="tenant-b", owner_id="user-a1")
    decision = engine.evaluate(subject=identity, action="vault.read", resource=resource)
    assert decision.allowed is False
    assert decision.reason == "TENANT_BOUNDARY_VIOLATION"


def test_admin_role_cannot_override_tenant_boundary():
    # This is the key architectural invariant: tenant isolation is checked
    # BEFORE the policy table, so no combination of role/scope can bypass it.
    identity = _identity(user_id="admin-a", tenant_id="tenant-a", roles=["admin"], scopes=[
        "vault:read", "vault:write", "vault:delete", "vault:share", "vault:admin",
    ])
    resource = _resource(tenant_id="tenant-b", owner_id="user-b1")
    decision = engine.evaluate(subject=identity, action="vault.read", resource=resource)
    assert decision.allowed is False
    assert decision.reason == "TENANT_BOUNDARY_VIOLATION"


def test_function_level_action_with_no_resource():
    identity = _identity(user_id="admin-a", roles=["admin"], scopes=["admin:write"])
    decision = engine.evaluate(subject=identity, action="admin.resources.create", resource=None)
    assert decision.allowed is True
    assert decision.reason == "ROLE_AND_SCOPE"


def test_function_level_action_denied_without_role():
    identity = _identity(user_id="user-a1", roles=["user"], scopes=["admin:write"])
    decision = engine.evaluate(subject=identity, action="admin.resources.create", resource=None)
    assert decision.allowed is False
    assert decision.reason == "INSUFFICIENT_ROLE_OR_SCOPE"
