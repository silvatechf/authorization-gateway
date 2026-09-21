"""Unit tests for the small pure-function helpers behind the policy table."""
from __future__ import annotations

from app.security.authorization.policy import POLICY_TABLE, has_all_scopes, has_any_role


def test_has_any_role_true_on_overlap():
    assert has_any_role(["user", "support"], ["admin", "support"]) is True


def test_has_any_role_false_without_overlap():
    assert has_any_role(["user"], ["admin"]) is False


def test_has_any_role_trivially_true_when_no_role_required():
    assert has_any_role([], []) is True


def test_has_all_scopes_requires_every_scope():
    assert has_all_scopes(["vault:read", "vault:write"], ["vault:read", "vault:write"]) is True
    assert has_all_scopes(["vault:read"], ["vault:read", "vault:write"]) is False


def test_has_all_scopes_trivially_true_when_no_scope_required():
    assert has_all_scopes([], []) is True


def test_every_registered_action_has_a_non_empty_role_requirement_or_is_owner_only():
    # Fail-closed sanity check on the table itself: an action must be
    # reachable by *some* combination of ownership or role+scope — a rule
    # with owner_allowed=False and an empty roles list would be permanently
    # unreachable, which is almost certainly a configuration mistake.
    for action, rule in POLICY_TABLE.items():
        assert rule.owner_allowed or rule.roles, f"{action} is unreachable: not owner-allowed and no roles"
