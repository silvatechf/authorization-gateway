"""
Vault resource endpoints.

These three routes are deliberately built to demonstrate BOTH BOLA
(Broken Object Level Authorization) and BFLA (Broken Function Level
Authorization) protection, per OWASP API Security Top 10:

  - BOLA: can user-a2 read/update/delete a vault item owned by user-a1
    or by a user in tenant-b, just by guessing/incrementing the id?
  - BFLA: can a non-admin caller reach the *delete* function at all,
    regardless of whose object it is?

Every request — allowed or denied — produces exactly one audit event.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from app.api.deps import get_correlation_id, get_identity, policy_engine
from app.data import store
from app.security.audit.events import emit_authorization_decision
from app.security.authorization.context import IdentityContext, ResourceContext

router = APIRouter(prefix="/api/v1/vault", tags=["vault"])


class VaultResourceOut(BaseModel):
    id: str
    tenant_id: str
    owner_id: str
    name: str
    secret_value: str


class VaultUpdateIn(BaseModel):
    secret_value: str


def _authorize_or_raise(
    request: Request,
    identity: IdentityContext,
    action: str,
    resource: ResourceContext,
    correlation_id: str,
) -> None:
    decision = policy_engine.evaluate(subject=identity, action=action, resource=resource)

    emit_authorization_decision(
        decision_allowed=decision.allowed,
        subject_id=identity.user_id,
        tenant_id=identity.tenant_id,
        resource_type=resource.resource_type,
        resource_id=resource.resource_id,
        action=action,
        policy=decision.policy,
        reason=decision.reason,
        correlation_id=correlation_id,
    )

    if decision.allowed:
        return

    # Cross-tenant denials return 404, not 403: confirming that a resource
    # with that id exists in a tenant the caller cannot see is itself an
    # information leak (resource enumeration). Same-tenant denials return
    # 403, since the caller is already allowed to know the object exists.
    if decision.reason == "TENANT_BOUNDARY_VIOLATION":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this action")


def _resource_context(resource) -> ResourceContext:
    return ResourceContext(
        resource_id=resource.id,
        resource_type="vault",
        tenant_id=resource.tenant_id,
        owner_id=resource.owner_id,
    )


@router.get("/{resource_id}", response_model=VaultResourceOut)
def read_vault_item(
    resource_id: str,
    request: Request,
    identity: IdentityContext = Depends(get_identity),
    correlation_id: str = Depends(get_correlation_id),
):
    resource = store.get_resource(resource_id)
    if resource is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

    _authorize_or_raise(request, identity, "vault.read", _resource_context(resource), correlation_id)
    return VaultResourceOut(**resource.__dict__)


@router.patch("/{resource_id}", response_model=VaultResourceOut)
def update_vault_item(
    resource_id: str,
    body: VaultUpdateIn,
    request: Request,
    identity: IdentityContext = Depends(get_identity),
    correlation_id: str = Depends(get_correlation_id),
):
    resource = store.get_resource(resource_id)
    if resource is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

    _authorize_or_raise(request, identity, "vault.update", _resource_context(resource), correlation_id)
    updated = store.update_resource_value(resource_id, body.secret_value)
    return VaultResourceOut(**updated.__dict__)


@router.delete("/{resource_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vault_item(
    resource_id: str,
    request: Request,
    identity: IdentityContext = Depends(get_identity),
    correlation_id: str = Depends(get_correlation_id),
):
    resource = store.get_resource(resource_id)
    if resource is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

    # BFLA demonstration: delete is NOT owner_allowed in the policy table,
    # so even the resource's own owner needs the admin role + vault:delete
    # scope. Ownership alone is not enough for this function.
    _authorize_or_raise(request, identity, "vault.delete", _resource_context(resource), correlation_id)
    store.delete_resource(resource_id)
