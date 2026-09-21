"""AuthorizationDecision is a small frozen value object — pin that down."""
from __future__ import annotations

import dataclasses

import pytest

from app.security.authorization.decision import AuthorizationDecision


def test_decision_holds_the_fields_it_is_given():
    decision = AuthorizationDecision(allowed=True, policy="vault.read", reason="OWNER")
    assert decision.allowed is True
    assert decision.policy == "vault.read"
    assert decision.reason == "OWNER"


def test_decision_is_immutable():
    decision = AuthorizationDecision(allowed=False, policy="vault.read", reason="INSUFFICIENT_ROLE_OR_SCOPE")
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.allowed = True  # type: ignore[misc]
