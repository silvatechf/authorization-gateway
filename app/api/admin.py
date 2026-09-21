"""
Admin-scoped endpoints. Both routes require the caller to hold the `admin`
role AND the matching scope — ownership never satisfies these, which is
the point: they demonstrate function-level authorization (BFLA) that is
independent of any single resource.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from app.api.deps import get_correlation_id, get_identity, policy_engine
from app.data import store
from app.security.audit.events import emit_authorization_decision, get_recent_events
from app.security.authorization.context import IdentityContext

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class ResourceCreateIn(BaseModel):
    owner_id: str
    name: str
    secret_value: str


class ResourceCreateOut(BaseModel):
    id: str
    tenant_id: str
    owner_id: str
    name: str


class AuditEventOut(BaseModel):
    timestamp: str
    decision: str
    subject_id: str
    tenant_id: str
    resource_type: str
    resource_id: str
    action: str
    policy: str
    reason: str
    correlation_id: str


def _authorize_function_or_raise(identity: IdentityContext, action: str, correlation_id: str) -> None:
    decision = policy_engine.evaluate(subject=identity, action=action, resource=None)
    emit_authorization_decision(
        decision_allowed=decision.allowed,
        subject_id=identity.user_id,
        tenant_id=identity.tenant_id,
        resource_type="admin_function",
        resource_id="-",
        action=action,
        policy=decision.policy,
        reason=decision.reason,
        correlation_id=correlation_id,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this action")


@router.post("/resources", response_model=ResourceCreateOut, status_code=status.HTTP_201_CREATED)
def create_resource(
    body: ResourceCreateIn,
    request: Request,
    identity: IdentityContext = Depends(get_identity),
    correlation_id: str = Depends(get_correlation_id),
):
    _authorize_function_or_raise(identity, "admin.resources.create", correlation_id)

    owner = store.get_user(body.owner_id)
    if owner is None or owner.tenant_id != identity.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="owner_id must belong to the caller's tenant",
        )

    resource = store.create_resource(
        tenant_id=identity.tenant_id,
        owner_id=body.owner_id,
        name=body.name,
        secret_value=body.secret_value,
    )
    return ResourceCreateOut(
        id=resource.id, tenant_id=resource.tenant_id, owner_id=resource.owner_id, name=resource.name
    )


@router.get("/audit", response_model=list[AuditEventOut])
def read_audit_log(
    request: Request,
    identity: IdentityContext = Depends(get_identity),
    correlation_id: str = Depends(get_correlation_id),
    limit: int = 100,
):
    _authorize_function_or_raise(identity, "admin.audit.read", correlation_id)

    # Tenant-scoped even for admins: an admin of tenant-a must never be able
    # to browse tenant-b's audit trail through this endpoint.
    events = [e for e in get_recent_events(limit=limit) if e.tenant_id == identity.tenant_id]
    return [AuditEventOut(**e.__dict__) for e in events]
