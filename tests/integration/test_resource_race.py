from app.data import store


def test_update_returns_404_if_resource_disappears_after_authorization(
    client, auth_header, monkeypatch
):
    original_update = store.update_resource_value

    def remove_resource_before_update(resource_id: str, new_value: str):
        store.delete_resource(resource_id)
        return original_update(resource_id, new_value)

    monkeypatch.setattr(
        store, "update_resource_value", remove_resource_before_update
    )

    response = client.patch(
        "/api/v1/vault/vault-a1",
        headers=auth_header("user-a1"),
        json={"secret_value": "updated-value"},
    )

    assert response.status_code == 404
