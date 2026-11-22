"""Security control tests: headers, CSRF, origin checks, rate limiting, RBAC."""

from fastapi.testclient import TestClient

from server.main import create_app
from tests.conftest import csrf_headers


def test_security_headers(client):
    response = client.get("/api/health")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Request-ID"]


def test_csrf_required_for_state_changes(client):
    response = client.post("/api/rooms", json={"name": "No CSRF"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_cross_origin_rejected(admin_client):
    headers = {"X-CSRF-Token": admin_client.cookies.get("cs_csrf"),
               "Origin": "https://evil.example"}
    response = admin_client.post("/api/rooms", json={"name": "Cross Origin"}, headers=headers)
    assert response.status_code == 403
    assert "Origin" in response.json()["error"]["message"]


def test_same_origin_allowed(admin_client):
    headers = {"X-CSRF-Token": admin_client.cookies.get("cs_csrf"),
               "Origin": "http://testserver"}
    response = admin_client.post("/api/rooms", json={"name": "Same Origin"}, headers=headers)
    assert response.status_code == 201


def test_member_cannot_read_audit(member_client):
    assert member_client.get("/api/audit").status_code == 403


def test_member_cannot_verify_sessions(member_client):
    response = member_client.post("/api/sessions/sess_missing/verify",
                                  headers={"X-CSRF-Token": member_client.cookies.get("cs_csrf")})
    assert response.status_code == 403


def test_validation_errors_do_not_echo_input(client):
    headers = csrf_headers(client)
    response = client.post("/api/auth/login",
                           json={"email": "not-an-email", "password": "secret-value"},
                           headers=headers)
    assert response.status_code == 422
    body = response.text
    assert "secret-value" not in body
    assert response.json()["error"]["details"][0]["field"] == "email"


def test_rate_limit_enforced(settings, tmp_path):
    limited = settings.model_copy(update={
        "database_url": f"sqlite:///{tmp_path}/rate.db",
        "model_dir": str(tmp_path / "models"),
        "auth_rate_limit_per_minute": 3,
    })
    app = create_app(limited)
    with TestClient(app) as client:
        headers = csrf_headers(client)
        statuses = []
        for _ in range(5):
            response = client.post("/api/auth/login",
                                   json={"email": "nobody@codeshield.dev", "password": "bad"},
                                   headers=headers)
            statuses.append(response.status_code)
        assert 429 in statuses
        assert "Retry-After" in response.headers


def test_openapi_and_docs_available(client):
    assert client.get("/api/openapi.json").status_code == 200
    assert client.get("/api/docs").status_code == 200


def test_spa_routes_serve_index(client):
    for path in ("/", "/login", "/register", "/app", "/dashboard"):
        response = client.get(path)
        assert response.status_code == 200
        assert "Code-Shield" in response.text


def test_admin_can_login_and_read_audit(admin_client):
    response = admin_client.get("/api/audit")
    assert response.status_code == 200
    assert any(event["action"].startswith("auth.") for event in response.json()["events"])
