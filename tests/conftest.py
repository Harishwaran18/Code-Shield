"""Shared pytest fixtures."""

import pytest
from fastapi.testclient import TestClient

from server.config import Settings
from server.main import create_app

ADMIN_EMAIL = "admin@codeshield.dev"
ADMIN_PASSWORD = "Admin-Shield-2026!"
MEMBER_PASSWORD = "Member-Shield-2026!"


@pytest.fixture(scope="session")
def settings(tmp_path_factory) -> Settings:
    tmp = tmp_path_factory.mktemp("codeshield")
    return Settings(
        secret_key="test-secret-key-that-is-long-enough-for-hs256!!",
        database_url=f"sqlite:///{tmp}/test.db",
        model_dir=str(tmp / "models"),
        admin_email=ADMIN_EMAIL,
        admin_password=ADMIN_PASSWORD,
        rate_limit_per_minute=100000,
        auth_rate_limit_per_minute=100000,
        cookie_secure=False,
    )


@pytest.fixture(scope="session")
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def csrf_headers(client: TestClient) -> dict:
    client.get("/api/auth/csrf")
    return {"X-CSRF-Token": client.cookies.get("cs_csrf")}


def login(client: TestClient, email: str = ADMIN_EMAIL, password: str = ADMIN_PASSWORD) -> dict:
    headers = csrf_headers(client)
    response = client.post("/api/auth/login", json={"email": email, "password": password},
                           headers=headers)
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": client.cookies.get("cs_csrf")}


def register(client: TestClient, name: str, email: str, password: str = MEMBER_PASSWORD):
    headers = csrf_headers(client)
    return client.post("/api/auth/register",
                       json={"name": name, "email": email, "password": password},
                       headers=headers)


@pytest.fixture
def admin_client(client):
    login(client)
    return client


@pytest.fixture
def member_client(app):
    with TestClient(app) as test_client:
        response = register(test_client, "Member User", "member@codeshield.dev")
        assert response.status_code in (201, 409), response.text
        if response.status_code == 409:
            login(test_client, "member@codeshield.dev", MEMBER_PASSWORD)
        yield test_client
