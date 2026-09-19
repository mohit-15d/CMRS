"""RBAC tests: role enforcement on protected routes and dependencies."""

import pytest
from fastapi import HTTPException

from app.api.deps import require_roles
from app.core.roles import ADMIN, INVESTIGATOR, VIEWER


class TestAdminEndpointMatrix:
    """The /api/admin/users route is the protected API example."""

    def test_admin_can_access_admin_endpoint(self, client, user_factory, login_headers):
        admin = user_factory(role=ADMIN)
        headers = login_headers(admin.username, "Passw0rd!x")
        resp = client.get("/api/admin/users", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert any(u["id"] == str(admin.id) for u in body)
        assert all("password_hash" not in u for u in body)

    def test_investigator_cannot_access_admin_endpoint(self, client, user_factory, login_headers):
        investigator = user_factory(role=INVESTIGATOR)
        headers = login_headers(investigator.username, "Passw0rd!x")
        resp = client.get("/api/admin/users", headers=headers)
        assert resp.status_code == 403

    def test_viewer_cannot_access_admin_endpoint(self, client, user_factory, login_headers):
        viewer = user_factory(role=VIEWER)
        headers = login_headers(viewer.username, "Passw0rd!x")
        resp = client.get("/api/admin/users", headers=headers)
        assert resp.status_code == 403

    def test_unauthenticated_cannot_access_protected(self, client):
        resp = client.get("/api/admin/users")
        assert resp.status_code == 401


class TestEvidenceUploadGate:
    """The dependency that evidence upload will use blocks viewers.

    Until evidence routes exist (later phase), this directly exercises the
    exact ``require_roles(INVESTIGATOR, ADMIN)`` gate that will protect
    ``POST /api/evidence/upload``.
    """

    def test_viewer_is_rejected(self, user_factory):
        viewer = user_factory(role=VIEWER)
        gate = require_roles(INVESTIGATOR, ADMIN)
        with pytest.raises(HTTPException) as exc:
            gate(current_user=viewer)
        assert exc.value.status_code == 403

    def test_investigator_is_allowed(self, user_factory):
        investigator = user_factory(role=INVESTIGATOR)
        gate = require_roles(INVESTIGATOR, ADMIN)
        assert gate(current_user=investigator) is investigator

    def test_admin_is_allowed(self, user_factory):
        admin = user_factory(role=ADMIN)
        gate = require_roles(INVESTIGATOR, ADMIN)
        assert gate(current_user=admin) is admin


class TestRegistrationRoleSafety:
    def test_client_supplied_admin_role_is_ignored(self, client):
        """A registration payload must never be able to self-assign a role."""
        resp = client.post(
            "/api/auth/register",
            json={
                "username": "crafty",
                "email": "crafty@example.com",
                "password": "Passw0rd!x",
                "role": ADMIN,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["role"] == VIEWER


class TestGenericInvalidLogin:
    def test_wrong_password_and_unknown_user_are_indistinguishable(
        self, client, user_factory
    ):
        user = user_factory(role=VIEWER)
        wrong_pw = client.post(
            "/api/auth/login",
            json={"username": user.username, "password": "Wrong-Pass1"},
        )
        unknown = client.post(
            "/api/auth/login",
            json={"username": "ghost_user", "password": "Whatever-1"},
        )
        assert wrong_pw.status_code == 401
        assert unknown.status_code == 401
        assert wrong_pw.json()["detail"] == unknown.json()["detail"]