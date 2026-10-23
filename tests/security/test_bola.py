"""
BOLA — Broken Object Level Authorization (OWASP API1:2023).

Attack shape: an authenticated, fully valid caller tampers with an object
identifier to reach an object they don't own, in the same tenant they
already belong to. The token is never the problem here — the
object-to-owner relationship is.
"""
from __future__ import annotations


def test_same_tenant_non_owner_cannot_read(client, auth_header):
    # Attacker: user-a2. Target: vault-a1, owned by user-a1. Same tenant.
    response = client.get("/api/v1/vault/vault-a1", headers=auth_header("user-a2"))
    assert response.status_code == 403


def test_same_tenant_non_owner_cannot_update(client, auth_header):
    response = client.patch(
        "/api/v1/vault/vault-a1",
        headers=auth_header("user-a2"),
        json={"secret_value": "attacker-value"},
    )
    assert response.status_code == 403


def test_denied_read_does_not_leak_the_secret_value(client, auth_header):
    response = client.get("/api/v1/vault/vault-a1", headers=auth_header("user-a2"))
    assert response.status_code == 403
    assert "s3cr3t-a1" not in response.text


def test_denied_update_does_not_mutate_the_resource(client, auth_header):
    response = client.patch(
        "/api/v1/vault/vault-a1",
        headers=auth_header("user-a2"),
        json={"secret_value": "attacker-value"},
    )

    assert response.status_code == 403

    # A denied request must not mutate the resource.
    owner_read = client.get(
        "/api/v1/vault/vault-a1",
        headers=auth_header("user-a1"),
    )
    assert owner_read.status_code == 200
    assert owner_read.json()["secret_value"] == "s3cr3t-a1"

def test_owner_relationship_is_re_checked_on_every_object_not_cached_by_caller(client, auth_header):
    # user-a1 legitimately owns vault-a1. They must NOT be able to reuse
    # that "owner" standing against a different object they don't own.
    create_response = client.post(
        "/api/v1/admin/resources",
        headers=auth_header("admin-a"),
        json={"owner_id": "user-a2", "name": "a2's secret", "secret_value": "s3cr3t-a2"},
    )
    other_object_id = create_response.json()["id"]

    response = client.get(f"/api/v1/vault/{other_object_id}", headers=auth_header("user-a1"))
    assert response.status_code == 403
