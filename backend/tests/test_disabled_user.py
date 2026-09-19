"""Disabled / inactive-account access tests (Stage 8 verification).

Covers: login rejection for inactive users, and rejection of an already-issued
JWT once the underlying user is deactivated.
"""

from tests.conftest import create_user


class TestDisabledUserAccess:
    def test_login_for_inactive_user_returns_403(self, client, db_session):
        user = create_user(db_session, username="disabled")
        user.is_active = False
        resp = client.post(
            "/api/auth/login",
            json={"username": user.username, "password": "Passw0rd!x"},
        )
        # Inactive account => 403 (distinct from wrong-password 401).
        assert resp.status_code == 403

    def test_token_invalid_after_user_deactivated(self, client, user_factory, login_headers):
        # Issue a token while active, then deactivate, then the token is refused.
        user = user_factory(username="laterdeact")
        headers = login_headers(user.username, "Passw0rd!x")
        assert client.get("/api/auth/me", headers=headers).status_code == 200

        # Deactivate directly on the ORM object within the same rolled-back tx.
        user.is_active = False

        assert client.get("/api/auth/me", headers=headers).status_code == 401
        assert client.get("/api/admin/users", headers=headers).status_code == 401

    def test_deactivated_admin_token_rejected(self, client, user_factory, login_headers):
        admin = user_factory(role="admin", username="deactadmin")
        headers = login_headers(admin.username, "Passw0rd!x")
        assert client.get("/api/admin/users", headers=headers).status_code == 200
        admin.is_active = False
        assert client.get("/api/admin/users", headers=headers).status_code == 401