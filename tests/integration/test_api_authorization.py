"""
Integration tests wiring authentication + authorization + the API layer
together through real HTTP calls (FastAPI TestClient). Security-specific
attack scenarios live under tests/security/; this file covers the
"happy path" plumbing: headers, status codes, correlation ids, and the
admin-create -> owner-read round trip.
"""
from __future__ import annotations


def test_missing_authorization_header_is_401(client):
    response = client.get("/api/v1/vault/vault-a1")
    assert response.status_code == 401


def test_malformed_authorization_scheme_is_401(client):
    response = client.get("/api/v1/vault/vault-a1", headers={"Authorization": "Token abc.def.ghi"})
    assert response.status_code == 401


def test_owner_can_read_own_resource(client, auth_header):
    response = client.get("/api/v1/vault/vault-a1", headers=auth_header("user-a1"))
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "vault-a1"
    assert body["owner_id"] == "user-a1"


def test_nonexistent_resource_in_own_tenant_is_404(client, auth_header):
    response = client.get("/api/v1/vault/vault-does-not-exist", headers=auth_header("user-a1"))
    assert response.status_code == 404


def test_correlation_id_is_generated_and_echoed(client, auth_header):
    response = client.get("/api/v1/vault/vault-a1", headers=auth_header("user-a1"))
    assert "x-correlation-id" in {k.lower() for k in response.headers}


def test_correlation_id_is_propagated_when_supplied(client, auth_header):
    headers = auth_header("user-a1")
    headers["X-Correlation-ID"] = "test-correlation-id-123"
    response = client.get("/api/v1/vault/vault-a1", headers=headers)
    assert response.headers["x-correlation-id"] == "test-correlation-id-123"


def test_admin_can_create_resource_and_owner_can_then_read_it(client, auth_header):
    create_response = client.post(
        "/api/v1/admin/resources",
        headers=auth_header("admin-a"),
        json={"owner_id": "user-a2", "name": "new secret", "secret_value": "new-value"},
    )
    assert create_response.status_code == 201
    new_id = create_response.json()["id"]

    read_response = client.get(f"/api/v1/vault/{new_id}", headers=auth_header("user-a2"))
    assert read_response.status_code == 200
    assert read_response.json()["secret_value"] == "new-value"


def test_admin_cannot_create_resource_for_a_user_in_another_tenant(client, auth_header):
    response = client.post(
        "/api/v1/admin/resources",
        headers=auth_header("admin-a"),
        json={"owner_id": "user-b1", "name": "cross-tenant attempt", "secret_value": "x"},
    )
    assert response.status_code == 400


def test_owner_can_update_own_resource(client, auth_header):
    response = client.patch(
        "/api/v1/vault/vault-a1",
        headers=auth_header("user-a1"),
        json={"secret_value": "rotated-value"},
    )
    assert response.status_code == 200
    assert response.json()["secret_value"] == "rotated-value"
