"""
BFLA — Broken Function Level Authorization (OWASP API5:2023).

Attack shape: the caller has legitimate access to an object (sometimes
they even own it) but tries to invoke a *function* on it that their
role/scope does not grant. Ownership must not silently upgrade into
function-level privilege.
"""
from __future__ import annotations


def test_owner_without_admin_role_cannot_delete_own_resource(client, auth_header):
    response = client.delete("/api/v1/vault/vault-a1", headers=auth_header("user-a1"))
    assert response.status_code == 403

    still_there = client.get("/api/v1/vault/vault-a1", headers=auth_header("user-a1"))
    assert still_there.status_code == 200


def test_admin_with_delete_scope_can_delete_in_own_tenant(client, auth_header):
    response = client.delete("/api/v1/vault/vault-a1", headers=auth_header("admin-a"))
    assert response.status_code == 204

    gone = client.get("/api/v1/vault/vault-a1", headers=auth_header("admin-a"))
    assert gone.status_code == 404


def test_non_admin_cannot_reach_admin_create_endpoint(client, auth_header):
    response = client.post(
        "/api/v1/admin/resources",
        headers=auth_header("user-a1"),
        json={"owner_id": "user-a1", "name": "self-granted", "secret_value": "x"},
    )
    assert response.status_code == 403


def test_non_admin_cannot_reach_admin_audit_endpoint(client, auth_header):
    response = client.get("/api/v1/admin/audit", headers=auth_header("user-a2"))
    assert response.status_code == 403


def test_ownership_of_the_target_object_does_not_unlock_the_admin_function(client, auth_header):
    # user-a1 owns vault-a1, but "share" is not a function they hold the
    # scope for either — being the owner of THIS object must not leak
    # into being allowed to call an admin-only function ABOUT this object.
    response = client.post(
        "/api/v1/admin/resources",
        headers=auth_header("user-a1"),
        json={"owner_id": "user-a1", "name": "owner trying admin fn", "secret_value": "x"},
    )
    assert response.status_code == 403
