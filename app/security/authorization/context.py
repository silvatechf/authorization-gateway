"""Value objects passed into the policy engine. No behaviour, just data."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IdentityContext:
    user_id: str
    tenant_id: str
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ResourceContext:
    resource_id: str
    resource_type: str
    tenant_id: str
    owner_id: str
