"""Integration tests for the /api/auth endpoints and existing /api/health."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt

from app.core.config import settings


def _token() -> str:
    return uuid4().hex[:10]


def _register_user(client, **overrides) -> dict:
    payload = {
        "username": f"user_{_token()}",
        "email": f"{_token()}@example.com",
        "password": "s3cret-pass!",
        "full_name": "Test User",
        **overrides,
    }
    resp = client.post("/api/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _login(client, username: str, password: str):
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


class TestRegister:
    def test_success_201_and_no_hash(self, client):
        body = _register_user(client)
        assert body["role"] == "viewer"
        assert body["is_active"] is True
        assert "id" in body and "created_at" in body
        assert "password_hash" not in body  # requirement: never return hashes

    def test_duplicate_username_409(self, client):
        username = f"user_{_token()}"
        _register_user(client, username=username)
        resp = client.post(
            "/api/auth/register",
            json={
                "username": username,
                "email": f"{_token()}@example.com",
                "password": "s3cret-pass!",
            },
        )
        assert resp.status_code == 409

    def test_duplicate_email_409(self, client):
        email = f"{_token()}@example.com"
        _register_user(client, email=email)
        resp = client.post(
            "/api/auth/register",
            json={
                "username": f"user_{_token()}",
                "email": email,
                "password": "s3cret-pass!",
            },
        )
        assert resp.status_code == 409

    def test_invalid_email_422(self, client):
        resp = client.post(
            "/api/auth/register",
            json={
                "username": f"user_{_token()}",
                "email": "not-an-email",
                "password": "s3cret-pass!",
            },
        )
        assert resp.status_code == 422

    def test_short_password_422(self, client):
        resp = client.post(
            "/api/auth/register",
            json={
                "username": f"user_{_token()}",
                "email": f"{_token()}@example.com",
                "password": "short",
            },
        )
        assert resp.status_code == 422

    def test_bad_username_422(self, client):
        resp = client.post(
            "/api/auth/register",
            json={
                "username": "ab",  # too short
                "email": f"{_token()}@example.com",
                "password": "s3cret-pass!",
            },
        )
        assert resp.status_code == 422


class TestLogin:
    def test_success_200_returns_access_token(self, client):
        username, password = self._fresh(client)
        resp = _login(client, username, password)
        assert resp.status_code == 200
        body = resp.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"]
        assert body["expires_in"] == settings.jwt_expire_minutes * 60

    def test_wrong_password_401(self, client):
        username, _ = self._fresh(client)
        resp = _login(client, username, "definitely-wrong")
        assert resp.status_code == 401

    def test_unknown_user_401(self, client):
        resp = _login(client, f"nobody_{_token()}", "s3cret-pass!")
        assert resp.status_code == 401

    @staticmethod
    def _fresh(client):
        user = _register_user(client)
        return user["username"], "s3cret-pass!"


class TestMe:
    def test_me_without_token_401(self, client):
        assert client.get("/api/auth/me").status_code == 401

    def test_me_with_valid_token_200(self, client):
        user = _register_user(client)
        login = _login(client, user["username"], "s3cret-pass!").json()
        headers = {"Authorization": f"Bearer {login['access_token']}"}
        resp = client.get("/api/auth/me", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == user["id"]
        assert "password_hash" not in resp.json()

    def test_me_with_expired_token_401(self, client):
        user = _register_user(client)
        expired = _signed_token(user["id"], in_the_past=True)
        resp = client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {expired}"}
        )
        assert resp.status_code == 401

    def test_me_with_garbage_token_401(self, client):
        resp = client.get(
            "/api/auth/me", headers={"Authorization": "Bearer not.a.jwt"}
        )
        assert resp.status_code == 401


def _signed_token(user_id: str, *, in_the_past: bool = False) -> str:
    now = datetime.now(timezone.utc)
    exp = now - timedelta(minutes=5) if in_the_past else now + timedelta(minutes=5)
    return jwt.encode(
        {"sub": user_id, "type": "access", "iat": now, "exp": exp},
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


class TestHealthStillWorks:
    def test_health_200(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_root_200(self, client):
        assert client.get("/").status_code == 200