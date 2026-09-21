"""
Declarative policy table.

This is intentionally NOT a pile of `if role == "admin"` checks scattered
across route handlers. Every action the gateway exposes is registered here
exactly once, with the conditions under which it is allowed. Adding a new
action means adding one entry here, not touching every endpoint.

Each PolicyRule expresses an OR between two paths to ALLOW:
  1. The caller owns the resource (if `owner_allowed` is True), OR
  2. The caller holds at least one of `roles` AND all of `scopes`.

Tenant isolation is enforced by the engine BEFORE this table is even
consulted (see engine.py) — no policy rule can override tenant isolation.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PolicyRule:
    owner_allowed: bool
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)


POLICY_TABLE: dict[str, PolicyRule] = {
    "vault.read": PolicyRule(owner_allowed=True, roles=["admin"], scopes=["vault:read"]),
    "vault.update": PolicyRule(owner_allowed=True, roles=["admin"], scopes=["vault:write"]),
    "vault.delete": PolicyRule(owner_allowed=False, roles=["admin"], scopes=["vault:delete"]),
    "vault.share": PolicyRule(owner_allowed=True, roles=["admin"], scopes=["vault:share"]),
    "vault.admin": PolicyRule(owner_allowed=False, roles=["admin"], scopes=["vault:admin"]),
    "admin.resources.create": PolicyRule(owner_allowed=False, roles=["admin"], scopes=["admin:write"]),
    "admin.audit.read": PolicyRule(owner_allowed=False, roles=["admin"], scopes=["admin:read"]),
}


def has_any_role(identity_roles: list[str], required_roles: list[str]) -> bool:
    if not required_roles:
        return True
    return bool(set(identity_roles) & set(required_roles))


def has_all_scopes(identity_scopes: list[str], required_scopes: list[str]) -> bool:
    if not required_scopes:
        return True
    return set(required_scopes).issubset(set(identity_scopes))
