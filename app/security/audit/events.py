"""
Structured audit logging for authorization decisions.

Hard rule: this module must NEVER receive or log a raw JWT, an
Authorization header, a password, a private key, or a refresh token. Only
already-derived, non-secret identifiers are accepted by AuditEvent's
fields, which makes it structurally hard to leak a credential through this
path by accident.
"""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

_audit_logger = logging.getLogger("audit")

# In-memory ring buffer backing the demo `GET /api/v1/admin/audit` endpoint.
# In a real deployment, audit events are consumed from the structured log
# stream (e.g. shipped to a SIEM) — this buffer exists only so the demo API
# has something to return without wiring up external log storage.
_MAX_BUFFER = 500
_buffer: list[AuditEvent] = []
_buffer_lock = threading.Lock()


@dataclass(frozen=True)
class AuditEvent:
    event: str
    decision: str
    subject_id: str
    tenant_id: str
    resource_type: str
    resource_id: str
    action: str
    policy: str
    reason: str
    correlation_id: str
    source: str = "authorization-gateway"
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


def emit_authorization_decision(
    *,
    decision_allowed: bool,
    subject_id: str,
    tenant_id: str,
    resource_type: str,
    resource_id: str,
    action: str,
    policy: str,
    reason: str,
    correlation_id: str,
) -> AuditEvent:
    event = AuditEvent(
        event="authorization.decision",
        decision="ALLOW" if decision_allowed else "DENY",
        subject_id=subject_id,
        tenant_id=tenant_id,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        policy=policy,
        reason=reason,
        correlation_id=correlation_id,
    )
    _audit_logger.info(json.dumps(asdict(event)))
    with _buffer_lock:
        _buffer.append(event)
        if len(_buffer) > _MAX_BUFFER:
            del _buffer[0]
    return event


def get_recent_events(limit: int = 100) -> list[AuditEvent]:
    with _buffer_lock:
        return list(_buffer[-limit:])
