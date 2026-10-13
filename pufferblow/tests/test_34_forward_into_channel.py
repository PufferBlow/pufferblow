from fastapi.testclient import TestClient

from pufferblow.core.bootstrap import api_initializer


def _user(username: str, *, owner: bool = False):
    user = api_initializer.user_manager.sign_up(username=username, password="a-long-password", is_owner=owner)
    tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=str(user.user_id), origin_server=user.origin_server
    )
    return user, tokens["access_token"]


def _channel(client: TestClient, token: str, name: str) -> str:
    response = client.post(
        "/api/v1/channels/create/",
        json={"auth_token": token, "channel_name": name, "is_private": False, "channel_type": "text"},
    )
    assert response.status_code == 200
    return response.json()["channel_data"]["channel_id"]


def _history(client: TestClient, token: str, channel_id: str) -> list[dict]:
    response = client.get(
        f"/api/v1/channels/{channel_id}/load_messages", params={"auth_token": token, "page": 1}
    )
    assert response.status_code == 200
    return response.json()["messages"]


def test_a_message_can_be_forwarded_into_another_channel_and_is_marked(client: TestClient):
    _, token = _user("forwarder", owner=True)
    source = _channel(client, token, "forward-source")
    target = _channel(client, token, "forward-target")

    sent = client.post(
        f"/api/v1/channels/{source}/send_message",
        data={"auth_token": token, "message": "worth passing on"},
    ).json()

    response = client.post(
        f"/api/v1/messages/{sent['message_id']}/forward",
        json={"auth_token": token, "channel_id": target},
    )
    assert response.status_code == 201, response.text
    assert response.json()["result"]["channel_id"] == target

    [forwarded] = _history(client, token, target)
    assert forwarded["message"] == "worth passing on"
    assert forwarded["forwarded_from_message_id"] == sent["message_id"]

    # The original is untouched and is not itself marked.
    [original] = _history(client, token, source)
    assert original["forwarded_from_message_id"] is None


def test_forwarding_needs_exactly_one_destination(client: TestClient):
    _, token = _user("forward_picky", owner=True)
    source = _channel(client, token, "picky-source")
    sent = client.post(
        f"/api/v1/channels/{source}/send_message", data={"auth_token": token, "message": "hi"}
    ).json()
    url = f"/api/v1/messages/{sent['message_id']}/forward"

    assert client.post(url, json={"auth_token": token}).status_code == 400
    assert client.post(url, json={"auth_token": token, "peer": "someone", "channel_id": source}).status_code == 400


def test_you_cannot_forward_into_a_channel_you_may_not_post_in(client: TestClient):
    _, owner_token = _user("forward_owner", owner=True)
    _, other_token = _user("forward_guest")
    source = _channel(client, owner_token, "open-source")
    private = client.post(
        "/api/v1/channels/create/",
        json={"auth_token": owner_token, "channel_name": "staff-only", "is_private": True, "channel_type": "text"},
    ).json()["channel_data"]["channel_id"]
    sent = client.post(
        f"/api/v1/channels/{source}/send_message", data={"auth_token": owner_token, "message": "hi"}
    ).json()

    response = client.post(
        f"/api/v1/messages/{sent['message_id']}/forward",
        json={"auth_token": other_token, "channel_id": private},
    )
    assert response.status_code in (403, 404)
    assert _history(client, owner_token, private) == []
