"""
Resource-enumeration resistance.

A cross-tenant denial and a genuinely nonexistent resource must be
indistinguishable to the caller — both return 404. If they didn't, a
caller could use the status code itself as an oracle to learn which
object ids exist in tenants they cannot see, which is its own
information-disclosure vulnerability even though the object is otherwise
unreachable.
"""
from __future__ import annotations


def test_cross_tenant_and_nonexistent_resource_return_the_same_status(client, auth_header):
    cross_tenant = client.get("/api/v1/vault/vault-b1", headers=auth_header("user-a1"))
    nonexistent = client.get("/api/v1/vault/vault-totally-made-up-id", headers=auth_header("user-a1"))

    assert cross_tenant.status_code == 404
    assert nonexistent.status_code == 404
    assert cross_tenant.json() == nonexistent.json()


def test_same_tenant_unauthorized_is_distinguishable_from_not_found(client, auth_header):
    # Within the caller's own tenant, existence is not a secret — a 403
    # here is fine, and different from the 404 used for cross-tenant /
    # nonexistent, because that distinction cannot be used to enumerate
    # objects in a tenant the caller has no visibility into anyway.
    same_tenant_unauthorized = client.get("/api/v1/vault/vault-a1", headers=auth_header("user-a2"))
    nonexistent = client.get("/api/v1/vault/vault-not-real", headers=auth_header("user-a2"))

    assert same_tenant_unauthorized.status_code == 403
    assert nonexistent.status_code == 404
