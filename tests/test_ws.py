"""WebSocket collaboration and dashboard feed tests."""

import pytest
from starlette.websockets import WebSocketDisconnect


def _headers(client):
    return {"X-CSRF-Token": client.cookies.get("cs_csrf")}


def _create_room(client, name="Socket Room"):
    response = client.post("/api/rooms", json={"name": name}, headers=_headers(client))
    assert response.status_code == 201, response.text
    return response.json()


def test_room_socket_requires_authentication(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/rooms/room_missing") as websocket:
            websocket.receive_json()


def test_room_socket_snapshot_chat_and_ping(admin_client):
    room = _create_room(admin_client)
    with admin_client.websocket_connect(f"/ws/rooms/{room['id']}") as websocket:
        snapshot = websocket.receive_json()
        assert snapshot["type"] == "snapshot"
        assert snapshot["room"]["id"] == room["id"]

        presence = websocket.receive_json()
        assert presence["type"] == "presence"
        assert presence["members"][0]["name"] == "Administrator"

        websocket.send_json({"type": "chat", "message": "hello team"})
        chat = websocket.receive_json()
        assert chat["type"] == "chat"
        assert chat["message"] == "hello team"

        websocket.send_json({"type": "ping"})
        assert websocket.receive_json()["type"] == "pong"


def test_room_socket_rejects_non_members(admin_client, member_client):
    room = _create_room(admin_client, "Members Only")
    with pytest.raises(WebSocketDisconnect):
        with member_client.websocket_connect(f"/ws/rooms/{room['id']}") as websocket:
            websocket.receive_json()


def test_edits_broadcast_between_clients(admin_client):
    room = _create_room(admin_client, "Broadcast Room")
    with admin_client.websocket_connect(f"/ws/rooms/{room['id']}") as first:
        first.receive_json()   # snapshot
        first.receive_json()   # presence
        with admin_client.websocket_connect(f"/ws/rooms/{room['id']}") as second:
            second.receive_json()  # snapshot
            second.receive_json()  # presence
            first.receive_json()   # presence for the second client

            first.send_json({"type": "edit", "code": "print('shared')"})
            edit = second.receive_json()
            assert edit["type"] == "edit"
            assert edit["code"] == "print('shared')"
            assert edit["user"]["name"] == "Administrator"


def test_dashboard_socket_streams_for_admin(admin_client):
    with admin_client.websocket_connect("/ws/dashboard") as websocket:
        payload = websocket.receive_json()
        assert "stats" in payload
        assert "sessions" in payload
        assert "risk_distribution" in payload


def test_dashboard_socket_rejects_members(member_client):
    with pytest.raises(WebSocketDisconnect):
        with member_client.websocket_connect("/ws/dashboard") as websocket:
            websocket.receive_json()
