"""Authentication, session and token lifecycle tests."""

from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, MEMBER_PASSWORD, csrf_headers, login, register


def test_weak_password_rejected(client):
    response = register(client, "Weak User", "weak@codeshield.dev", "password")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_registration_requires_csrf(client):
    response = client.post("/api/auth/register",
                           json={"name": "No CSRF", "email": "nocsrf@codeshield.dev",
                                 "password": MEMBER_PASSWORD})
    assert response.status_code == 403


def test_duplicate_email_rejected(client):
    assert register(client, "First", "dupe@codeshield.dev").status_code == 201
    assert register(client, "Second", "dupe@codeshield.dev").status_code == 409


def test_login_sets_hardened_cookies(client):
    headers = csrf_headers(client)
    response = client.post("/api/auth/login",
                           json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                           headers=headers)
    assert response.status_code == 200
    set_cookie = " ".join(response.headers.get_list("set-cookie"))
    assert "cs_access=" in set_cookie and "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie.replace("samesite", "SameSite")


def test_login_rejects_bad_password(client):
    headers = csrf_headers(client)
    response = client.post("/api/auth/login",
                           json={"email": ADMIN_EMAIL, "password": "wrong-password"},
                           headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Invalid email or password"


def test_me_requires_authentication(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_logout_revokes_session(admin_client):
    headers = {"X-CSRF-Token": admin_client.cookies.get("cs_csrf")}
    assert admin_client.post("/api/auth/logout", headers=headers).status_code == 200
    assert admin_client.get("/api/auth/me").status_code == 401


def test_refresh_token_rotation_and_reuse_detection(client):
    headers = login(client)
    old_refresh = client.cookies.get("cs_refresh")
    assert old_refresh

    headers = {"X-CSRF-Token": client.cookies.get("cs_csrf")}
    assert client.post("/api/auth/refresh", headers=headers).status_code == 200

    # Replaying the rotated token must fail and revoke the session.
    client.cookies.set("cs_refresh", old_refresh, path="/api/auth")
    headers = {"X-CSRF-Token": client.cookies.get("cs_csrf")}
    assert client.post("/api/auth/refresh", headers=headers).status_code == 401
    assert client.get("/api/auth/me").status_code == 401


def test_account_lockout_after_failures(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        register(client, "Locked User", "locked@codeshield.dev")
        client.post("/api/auth/logout",
                    headers={"X-CSRF-Token": client.cookies.get("cs_csrf")})
        headers = csrf_headers(client)
        for _ in range(5):
            client.post("/api/auth/login",
                        json={"email": "locked@codeshield.dev", "password": "bad-password"},
                        headers=headers)
            headers = {"X-CSRF-Token": client.cookies.get("cs_csrf")}
        response = client.post("/api/auth/login",
                               json={"email": "locked@codeshield.dev",
                                     "password": MEMBER_PASSWORD},
                               headers=headers)
        assert response.status_code == 429


def test_change_password_revokes_other_sessions(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as first, TestClient(app) as second:
        register(first, "Password User", "pwuser@codeshield.dev")
        login(second, "pwuser@codeshield.dev", MEMBER_PASSWORD)

        headers = {"X-CSRF-Token": first.cookies.get("cs_csrf")}
        response = first.post("/api/auth/password",
                              json={"current_password": MEMBER_PASSWORD,
                                    "new_password": "Rotated-Shield-2027!"},
                              headers=headers)
        assert response.status_code == 200
        assert second.get("/api/auth/me").status_code == 401
        login(second, "pwuser@codeshield.dev", "Rotated-Shield-2027!")
