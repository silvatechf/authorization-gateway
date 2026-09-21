"""
The authorization matrix, made executable.

This is the same table documented in the README under "Authorization
matrix (as seeded)" — turned into a parametrized test so that a future
change to the policy table or the seed data cannot silently drift away
from what the documentation claims without a test failing.
"""
from __future__ import annotations

import pytest

# (user_id, resource_id, http_method, expected_status)
MATRIX = [
    ("user-a1", "vault-a1", "GET", 200),      # owner reads own resource
    ("user-a1", "vault-a1", "DELETE", 403),   # owner, but delete needs admin (BFLA)
    ("user-a2", "vault-a1", "GET", 403),      # same tenant, not owner, no admin (BOLA)
    ("admin-a", "vault-a1", "GET", 200),      # admin, same tenant, any object
    ("admin-a", "vault-a1", "DELETE", 204),   # admin, same tenant -> allowed
    ("user-b1", "vault-a1", "GET", 404),      # cross-tenant -> not found, not forbidden
    ("admin-a", "vault-b1", "GET", 404),      # admin cannot cross tenant boundary either
]


@pytest.mark.parametrize("user_id,resource_id,method,expected_status", MATRIX)
def test_authorization_matrix(client, auth_header, user_id, resource_id, method, expected_status):
    headers = auth_header(user_id)
    if method == "GET":
        response = client.get(f"/api/v1/vault/{resource_id}", headers=headers)
    elif method == "DELETE":
        response = client.delete(f"/api/v1/vault/{resource_id}", headers=headers)
    else:  # pragma: no cover - matrix only uses GET/DELETE today
        raise AssertionError(f"unsupported method in matrix: {method}")

    assert response.status_code == expected_status, (
        f"{user_id} {method} {resource_id}: expected {expected_status}, got {response.status_code}"
    )


def test_no_token_is_always_401_regardless_of_resource(client):
    response = client.get("/api/v1/vault/vault-a1")
    assert response.status_code == 401
