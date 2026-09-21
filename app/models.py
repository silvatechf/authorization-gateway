"""Domain models shared across the API layer and the data store."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class User:
    id: str
    tenant_id: str
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)


@dataclass
class VaultResource:
    id: str
    tenant_id: str
    owner_id: str
    name: str
    secret_value: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
