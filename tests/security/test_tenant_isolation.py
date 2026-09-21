"""
Multi-tenant boundary tests.

The single worst failure mode for a multi-tenant SaaS backend is a
customer of tenant A reading, modifying or deleting a customer of tenant
B's data. These tests assert that boundary holds even under the most
favorable conditions for an attacker: a fully valid, unexpired,
correctly-signed admin token from the wrong tenant.
"""
from __future__ import annotations


def test_cross_tenant_read_is_denied(client, auth_header):
    response = client.get("/api/v1/vault/vault-b1", headers=auth_header("user-a1"))
    assert response.status_code == 404  # see test_enumeration.py for why 404, not 403


def test_cross_tenant_update_is_denied(client, auth_header):
    response = client.patch(
        "/api/v1/vault/vault-b1",
        headers=auth_header("user-a1"),
        json={"secret_value": "cross-tenant-write"},
    )
    assert response.status_code == 404


def test_cross_tenant_delete_is_denied(client, auth_header):
    response = client.delete("/api/v1/vault/vault-b1", headers=auth_header("user-a1"))
    assert response.status_code == 404


def test_admin_role_does_not_grant_cross_tenant_access(client, auth_header):
    # admin-a is a fully privileged admin — but only within tenant-a.
    # A real IAM incident is exactly "admin of the wrong tenant".
    response = client.get("/api/v1/vault/vault-b1", headers=auth_header("admin-a"))
    assert response.status_code == 404


def test_admin_role_does_not_grant_cross_tenant_delete(client, auth_header):
    response = client.delete("/api/v1/vault/vault-b1", headers=auth_header("admin-a"))
    assert response.status_code == 404

    still_there = client.get("/api/v1/vault/vault-b1", headers=auth_header("user-b1"))
    assert still_there.status_code == 200


def test_admin_audit_log_never_returns_another_tenants_events(client, auth_header):
    # Generate an event in tenant-b by having user-b1 read their own resource.
    client.get("/api/v1/vault/vault-b1", headers=auth_header("user-b1"))
    # And an event in tenant-a.
    client.get("/api/v1/vault/vault-a1", headers=auth_header("user-a1"))

    tenant_a_audit = client.get("/api/v1/admin/audit", headers=auth_header("admin-a"))
    assert tenant_a_audit.status_code == 200
    tenant_ids_seen = {event["tenant_id"] for event in tenant_a_audit.json()}
    assert tenant_ids_seen <= {"tenant-a"}
    assert "tenant-b" not in tenant_ids_seen
