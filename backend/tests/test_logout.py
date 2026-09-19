"""Logout (JWT revocation) tests plus token-store unit tests."""

from app.security.token_store import TokenStore


class TestTokenStoreUnit:
    def test_revoke_and_is_revoked(self):
        store = TokenStore()
        store.revoke("abc", expires_at=9_999_999_999)
        assert store.is_revoked("abc") is True
        assert store.is_revoked("other") is False

    def test_reset(self):
        store = TokenStore()
        store.revoke("abc", expires_at=9_999_999_999)
        store.reset()
        assert store.is_revoked("abc") is False


class TestLogoutEndpoint:
    def test_revoked_token_rejected_after_logout(self, client, user_factory, login_headers):
        user = user_factory()
        headers = login_headers(user.username, "Passw0rd!x")
        assert client.get("/api/auth/me", headers=headers).status_code == 200

        resp = client.post("/api/auth/logout", headers=headers)
        assert resp.status_code == 204

        # The same (still unexpired) token is now revoked.
        assert client.get("/api/auth/me", headers=headers).status_code == 401

    def test_other_token_still_valid_after_logout(self, client, user_factory, login_headers):
        user = user_factory()
        headers_a = login_headers(user.username, "Passw0rd!x")
        headers_b = login_headers(user.username, "Passw0rd!x")
        assert client.post("/api/auth/logout", headers=headers_a).status_code == 204
        assert client.get("/api/auth/me", headers=headers_b).status_code == 200

    def test_logout_without_token_returns_401(self, client):
        assert client.post("/api/auth/logout").status_code == 401

    def test_logout_with_invalid_token_returns_401(self, client):
        resp = client.post(
            "/api/auth/logout",
            headers={"Authorization": "Bearer not.a.jwt"},
        )
        assert resp.status_code == 401