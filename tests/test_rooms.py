"""Collaboration room lifecycle and authorisation tests."""


def _headers(client):
    return {"X-CSRF-Token": client.cookies.get("cs_csrf")}


def test_room_lifecycle(admin_client):
    headers = _headers(admin_client)
    created = admin_client.post("/api/rooms", json={"name": "Team Room", "language": "python"},
                                headers=headers)
    assert created.status_code == 201
    room = created.json()
    assert room["members"] == 1

    listing = admin_client.get("/api/rooms").json()
    assert any(item["id"] == room["id"] for item in listing)

    updated = admin_client.put(f"/api/rooms/{room['id']}/code",
                               json={"code": "print('hi')", "language": "javascript"},
                               headers=headers)
    assert updated.status_code == 200
    assert updated.json()["language"] == "javascript"

    members = admin_client.get(f"/api/rooms/{room['id']}/members").json()["members"]
    assert len(members) == 1 and members[0]["role"] == "owner"

    assert admin_client.delete(f"/api/rooms/{room['id']}", headers=headers).status_code == 204
    assert admin_client.get(f"/api/rooms/{room['id']}").status_code == 404


def test_non_member_cannot_read_room(admin_client, member_client):
    headers = _headers(admin_client)
    room = admin_client.post("/api/rooms", json={"name": "Secret Room"}, headers=headers).json()
    assert member_client.get(f"/api/rooms/{room['id']}").status_code == 403


def test_member_can_join_and_edit(admin_client, member_client):
    headers = _headers(admin_client)
    room = admin_client.post("/api/rooms", json={"name": "Shared Room"}, headers=headers).json()

    joined = member_client.post(f"/api/rooms/{room['id']}/join", headers=_headers(member_client))
    assert joined.status_code == 200
    assert joined.json()["members"] == 2

    edit = member_client.put(f"/api/rooms/{room['id']}/code",
                             json={"code": "print('shared')"}, headers=_headers(member_client))
    assert edit.status_code == 200

    assert member_client.get(f"/api/rooms/{room['id']}").status_code == 200


def test_owner_cannot_leave_room(admin_client):
    headers = _headers(admin_client)
    room = admin_client.post("/api/rooms", json={"name": "Owner Room"}, headers=headers).json()
    assert admin_client.post(f"/api/rooms/{room['id']}/leave", headers=headers).status_code == 400


def test_member_cannot_delete_room(admin_client, member_client):
    headers = _headers(admin_client)
    room = admin_client.post("/api/rooms", json={"name": "Protected Room"}, headers=headers).json()
    member_client.post(f"/api/rooms/{room['id']}/join", headers=_headers(member_client))
    assert member_client.delete(f"/api/rooms/{room['id']}",
                                headers=_headers(member_client)).status_code == 403


def test_room_requires_authentication(client):
    assert client.get("/api/rooms").status_code == 401
