"""
The Policy Engine.

`evaluate()` is the ONLY place in the codebase that is allowed to decide
ALLOW/DENY. Route handlers call it and act on the result; they never
re-derive authorization logic themselves.

Evaluation order (each step can short-circuit to DENY):
  1. Unknown action            -> DENY (fail closed on programmer error)
  2. Tenant boundary            -> DENY if resource.tenant_id != subject.tenant_id
  3. Ownership                  -> ALLOW if rule.owner_allowed and subject owns resource
  4. Role + scope                -> ALLOW if subject has a required role AND all required scopes
  5. Otherwise                  -> DENY
"""
from __future__ import annotations

from app.security.authorization.context import IdentityContext, ResourceContext
from app.security.authorization.decision import AuthorizationDecision
from app.security.authorization.policy import POLICY_TABLE, has_all_scopes, has_any_role


class PolicyEngine:
    def evaluate(
        self,
        subject: IdentityContext,
        action: str,
        resource: ResourceContext | None = None,
        context: dict | None = None,
    ) -> AuthorizationDecision:
        rule = POLICY_TABLE.get(action)
        if rule is None:
            return AuthorizationDecision(allowed=False, policy=action, reason="UNKNOWN_ACTION")

        if resource is not None and resource.tenant_id != subject.tenant_id:
            return AuthorizationDecision(
                allowed=False, policy=action, reason="TENANT_BOUNDARY_VIOLATION"
            )

        if resource is not None and rule.owner_allowed and subject.user_id == resource.owner_id:
            return AuthorizationDecision(allowed=True, policy=action, reason="OWNER")

        if has_any_role(subject.roles, rule.roles) and has_all_scopes(subject.scopes, rule.scopes):
            return AuthorizationDecision(allowed=True, policy=action, reason="ROLE_AND_SCOPE")

        return AuthorizationDecision(allowed=False, policy=action, reason="INSUFFICIENT_ROLE_OR_SCOPE")
