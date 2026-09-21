from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    policy: str
    reason: str
