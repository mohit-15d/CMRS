"""Admin user-management tests: create/update/reset, RBAC, last-admin guard."""


def _admin_headers(client, user_factory, login_headers):
    admin = user_factory(role="admin", username="boss")
    return login_headers(admin.username, "Passw0rd!x")


class TestAdminCreateUser:
    def test_create_user_with_role(self, client, user_factory, login_headers):
        headers = _admin_headers(client, user_factory, login_headers)
        resp = client.post(
            "/api/admin/users",
            headers=headers,
            json={
                "username": "inv1",
                "email": "inv1@example.com",
                "password": "Passw0rd!x",
                "role": "investigator",
                "full_name": "Ivy Invest",
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["role"] == "investigator"
        assert body["is_active"] is True
        assert "password_hash" not in body

    def test_duplicate_409(self, client, user_factory, login_headers):
        headers = _admin_headers(client, user_factory, login_headers)
        payload = {
            "username": "dup",
            "email": "dup@example.com",
            "password": "Passw0rd!x",
            "role": "viewer",
        }
        assert client.post("/api/admin/users", headers=headers, json=payload).status_code == 201
        assert client.post("/api/admin/users", headers=headers, json=payload).status_code == 409

    def test_invalid_role_422(self, client, user_factory, login_headers):
        headers = _admin_headers(client, user_factory, login_headers)
        resp = client.post(
            "/api/admin/users",
            headers=headers,
            json={
                "username": "hacker",
                "email": "hacker@example.com",
                "password": "Passw0rd!x",
                "role": "superuser",
            },
        )
        assert resp.status_code == 422

    def test_requires_admin_403(self, client, user_factory, login_headers):
        investigate = user_factory(role="investigator")
        headers = login_headers(investigate.username, "Passw0rd!x")
        resp = client.post(
            "/api/admin/users",
            headers=headers,
            json={
                "username": "x",
                "email": "x@example.com",
                "password": "Passw0rd!x",
                "role": "viewer",
            },
        )
        assert resp.status_code == 403

    def test_unauthenticated_401(self, client):
        assert client.post("/api/admin/users", json={}).status_code == 401


class TestAdminUpdateUser:
    def test_change_role(self, client, user_factory, login_headers):
        headers = _admin_headers(client, user_factory, login_headers)
        viewer = user_factory(role="viewer", username="v1")
        resp = client.patch(
            f"/api/admin/users/{viewer.id}",
            headers=headers,
            json={"role": "investigator"},
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "investigator"

    def test_deactivate_user(self, client, user_factory, login_headers):
        headers = _admin_headers(client, user_factory, login_headers)
        viewer = user_factory(role="viewer", username="v2")
        resp = client.patch(
            f"/api/admin/users/{viewer.id}",
            headers=headers,
            json={"is_active": False},
        )
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

    def test_empty_update_422(self, client, user_factory, login_headers):
        headers = _admin_headers(client, user_factory, login_headers)
        viewer = user_factory(role="viewer", username="v3")
        resp = client.patch(f"/api/admin/users/{viewer.id}", headers=headers, json={})
        assert resp.status_code == 422

    def test_unknown_user_404(self, client, user_factory, login_headers):
        headers = _admin_headers(client, user_factory, login_headers)
        resp = client.patch(
            "/api/admin/users/00000000-0000-0000-0000-000000000000",
            headers=headers,
            json={"is_active": False},
        )
        assert resp.status_code == 404

    def test_cannot_deactivate_last_admin(
        self, client, user_factory, login_headers
    ):
        # A single active admin in the test DB is the "last active admin" and
        # must NOT be able to deactivate or demote themselves / the only admin.
        admin = user_factory(role="admin", username="solo")
        headers = login_headers(admin.username, "Passw0rd!x")
        resp = client.patch(
            f"/api/admin/users/{admin.id}",
            headers=headers,
            json={"is_active": False},
        )
        assert resp.status_code == 400


class TestAdminResetPassword:
    def test_reset_then_login_with_new(self, client, user_factory, login_headers):
        headers = _admin_headers(client, user_factory, login_headers)
        viewer = user_factory(role="viewer", username="pw1")
        resp = client.post(
            f"/api/admin/users/{viewer.id}/reset-password",
            headers=headers,
            json={"new_password": "BrandNewPass!1"},
        )
        assert resp.status_code == 204
        assert (
            client.post(
                "/api/auth/login",
                json={"username": "pw1", "password": "Passw0rd!x"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/auth/login",
                json={"username": "pw1", "password": "BrandNewPass!1"},
            ).status_code
            == 200
        )