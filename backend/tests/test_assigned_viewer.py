"""Tests for the assigned-reviewer (viewer) access feature.

Stage 21: a case whose ``assigned_investigator_id`` points at a viewer grants
that viewer read-only access on the case list/detail endpoints. Viewers may
read cases they are assigned to but may never write to them. Only admins may
re-assign a reviewer; only admins/investigators may update a case at all.
"""

from uuid import uuid4

CASE_PAYLOAD = {
    "case_number": "CASE-VIEW-1",
    "title": "Viewer access case",
    "description": "Assigned viewer can read but not write",
    "offense": "Burglary",
    "victim": "ACME Corp",
    "suspect": "Unknown",
    "submitting_officer": "Det. Viewer",
    "location": "123 Main St",
    "status": "open",
}


def _user(user_factory, role, username):
    return user_factory(role=role, username=username)


def _headers(login_headers, user):
    return login_headers(user.username, "Passw0rd!x")


def _make_case(client, headers, case_number):
    resp = client.post(
        "/api/cases", headers=headers, json=dict(CASE_PAYLOAD, case_number=case_number)
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestAssignedViewerRead:
    def test_viewer_can_view_case_assigned_to_them(
        self, client, user_factory, login_headers
    ):
        admin_user = _user(user_factory, "admin", "adm_v1")
        admin = _headers(login_headers, admin_user)
        case = _make_case(client, admin, "CASE-VIEW-1")

        viewer_user = _user(user_factory, "viewer", "view_v1")
        viewer = _headers(login_headers, viewer_user)

        assign = client.patch(
            f"/api/cases/{case['id']}",
            headers=admin,
            json={"assigned_investigator_id": str(viewer_user.id)},
        )
        assert assign.status_code == 200, assign.text
        assert assign.json()["assigned_investigator_id"] == str(viewer_user.id)

        got = client.get(f"/api/cases/{case['id']}", headers=viewer)
        assert got.status_code == 200, got.text
        assert got.json()["assigned_investigator_id"] == str(viewer_user.id)
        assert got.json()["title"] == case["title"]

    def test_viewer_can_list_assigned_case(
        self, client, user_factory, login_headers
    ):
        admin_user = _user(user_factory, "admin", "adm_v2")
        admin = _headers(login_headers, admin_user)
        case = _make_case(client, admin, "CASE-VIEW-2")

        viewer_user = _user(user_factory, "viewer", "view_v2")
        viewer = _headers(login_headers, viewer_user)
        client.patch(
            f"/api/cases/{case['id']}",
            headers=admin,
            json={"assigned_investigator_id": str(viewer_user.id)},
        )

        listed = client.get("/api/cases", headers=viewer)
        assert listed.status_code == 200
        ids = [c["id"] for c in listed.json()]
        assert case["id"] in ids

    def test_viewer_list_only_assigned_cases(
        self, client, user_factory, login_headers
    ):
        admin_user = _user(user_factory, "admin", "adm_v3")
        admin = _headers(login_headers, admin_user)
        case_a = _make_case(client, admin, "CASE-VIEW-3A")
        case_b = _make_case(client, admin, "CASE-VIEW-3B")

        viewer_a = _user(user_factory, "viewer", "view_v3a")
        viewer_b = _user(user_factory, "viewer", "view_v3b")

        client.patch(
            f"/api/cases/{case_a['id']}",
            headers=admin,
            json={"assigned_investigator_id": str(viewer_a.id)},
        )
        client.patch(
            f"/api/cases/{case_b['id']}",
            headers=admin,
            json={"assigned_investigator_id": str(viewer_b.id)},
        )

        listed = client.get(
            "/api/cases", headers=_headers(login_headers, viewer_a)
        )
        assert listed.status_code == 200
        ids = [c["id"] for c in listed.json()]
        assert case_a["id"] in ids
        assert case_b["id"] not in ids

    def test_viewer_cannot_view_unassigned_case(
        self, client, user_factory, login_headers
    ):
        owner_user = _user(user_factory, "investigator", "own_v4")
        owner = _headers(login_headers, owner_user)
        case = _make_case(client, owner, "CASE-VIEW-4")

        viewer_user = _user(user_factory, "viewer", "view_v4")
        viewer = _headers(login_headers, viewer_user)

        resp = client.get(f"/api/cases/{case['id']}", headers=viewer)
        assert resp.status_code == 403

    def test_assigned_viewer_cannot_update(
        self, client, user_factory, login_headers
    ):
        admin_user = _user(user_factory, "admin", "adm_v5")
        admin = _headers(login_headers, admin_user)
        case = _make_case(client, admin, "CASE-VIEW-5")

        viewer_user = _user(user_factory, "viewer", "view_v5")
        viewer = _headers(login_headers, viewer_user)
        client.patch(
            f"/api/cases/{case['id']}",
            headers=admin,
            json={"assigned_investigator_id": str(viewer_user.id)},
        )

        upd = client.patch(
            f"/api/cases/{case['id']}",
            headers=viewer,
            json={"status": "closed"},
        )
        assert upd.status_code == 403


class TestAssignmentValidation:
    def test_admin_can_assign_reviewer(
        self, client, user_factory, login_headers
    ):
        admin_user = _user(user_factory, "admin", "adm_a1")
        admin = _headers(login_headers, admin_user)
        case = _make_case(client, admin, "CASE-ASSIGN-1")

        reviewer = _user(user_factory, "viewer", "rev_a1")
        resp = client.patch(
            f"/api/cases/{case['id']}",
            headers=admin,
            json={"assigned_investigator_id": str(reviewer.id)},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["assigned_investigator_id"] == str(reviewer.id)

    def test_assign_to_unknown_user_422(
        self, client, user_factory, login_headers
    ):
        admin_user = _user(user_factory, "admin", "adm_a2")
        admin = _headers(login_headers, admin_user)
        case = _make_case(client, admin, "CASE-ASSIGN-2")

        resp = client.patch(
            f"/api/cases/{case['id']}",
            headers=admin,
            json={"assigned_investigator_id": str(uuid4())},
        )
        assert resp.status_code == 422

    def test_assign_to_inactive_user_422(
        self, client, user_factory, login_headers, db_session
    ):
        admin_user = _user(user_factory, "admin", "adm_a3")
        admin = _headers(login_headers, admin_user)
        case = _make_case(client, admin, "CASE-ASSIGN-3")

        inactive = _user(user_factory, "viewer", "rev_a3_inactive")
        inactive.is_active = False
        db_session.flush()

        resp = client.patch(
            f"/api/cases/{case['id']}",
            headers=admin,
            json={"assigned_investigator_id": str(inactive.id)},
        )
        assert resp.status_code == 422

    def test_viewer_cannot_assign(
        self, client, user_factory, login_headers
    ):
        owner_user = _user(user_factory, "investigator", "own_b1")
        owner = _headers(login_headers, owner_user)
        case = _make_case(client, owner, "CASE-ASSIGN-4")

        reviewer = _user(user_factory, "viewer", "rev_b1")
        resp = client.patch(
            f"/api/cases/{case['id']}",
            headers=_headers(login_headers, reviewer),
            json={"assigned_investigator_id": str(reviewer.id)},
        )
        assert resp.status_code == 403

