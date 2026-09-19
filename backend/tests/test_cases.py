"""Case management tests: CRUD, RBAC, ownership/IDOR prevention."""

from uuid import uuid4


def _headers(user_factory, login_headers, role, username):
    u = user_factory(role=role, username=username)
    return login_headers(u.username, "Passw0rd!x")


CASE_PAYLOAD = {
    "case_number": "CASE-1001",
    "title": "Burglary investigation",
    "description": "Break-in at warehouse",
    "offense": "Burglary",
    "victim": "ACME Corp",
    "suspect": "Unknown",
    "submitting_officer": "Det. Smith",
    "location": "123 Main St",
    "status": "open",
}


class TestCaseAuthentication:
    def test_unauthenticated_cannot_create(self, client):
        assert client.post("/api/cases", json=CASE_PAYLOAD).status_code == 401

    def test_unauthenticated_cannot_list(self, client):
        assert client.get("/api/cases").status_code == 401

    def test_unauthenticated_cannot_view(self, client):
        assert client.get(f"/api/cases/{uuid4()}").status_code == 401


class TestCaseCreate:
    def test_investigator_creates(self, client, user_factory, login_headers):
        headers = _headers(user_factory, login_headers, "investigator", "inv_creator")
        resp = client.post("/api/cases", headers=headers, json=CASE_PAYLOAD)
        assert resp.status_code == 201
        body = resp.json()
        assert body["case_number"] == "CASE-1001"
        assert body["status"] == "open"
        assert "created_at" in body and "id" in body

    def test_admin_creates(self, client, user_factory, login_headers):
        headers = _headers(user_factory, login_headers, "admin", "adm_creator")
        resp = client.post("/api/cases", headers=headers, json=CASE_PAYLOAD)
        assert resp.status_code == 201

    def test_viewer_cannot_create(self, client, user_factory, login_headers):
        headers = _headers(user_factory, login_headers, "viewer", "view_creator")
        resp = client.post("/api/cases", headers=headers, json=CASE_PAYLOAD)
        assert resp.status_code == 403

    def test_duplicate_case_number_409(self, client, user_factory, login_headers):
        headers = _headers(user_factory, login_headers, "investigator", "inv_dup")
        assert client.post("/api/cases", headers=headers, json=CASE_PAYLOAD).status_code == 201
        assert client.post("/api/cases", headers=headers, json=CASE_PAYLOAD).status_code == 409

    def test_invalid_status_422(self, client, user_factory, login_headers):
        headers = _headers(user_factory, login_headers, "investigator", "inv_status")
        payload = dict(CASE_PAYLOAD, case_number="CASE-77", status="archived")
        assert client.post("/api/cases", headers=headers, json=payload).status_code == 422

    def test_missing_title_422(self, client, user_factory, login_headers):
        headers = _headers(user_factory, login_headers, "investigator", "inv_title")
        payload = dict(CASE_PAYLOAD, case_number="CASE-88")
        payload.pop("title")
        assert client.post("/api/cases", headers=headers, json=payload).status_code == 422


class TestCaseListScoping:
    def test_investigator_sees_own_cases_only(self, client, user_factory, login_headers):
        inv1 = _headers(user_factory, login_headers, "investigator", "inv_a")
        inv2 = _headers(user_factory, login_headers, "investigator", "inv_b")
        client.post("/api/cases", headers=inv1, json=dict(CASE_PAYLOAD, case_number="AAA"))
        client.post("/api/cases", headers=inv2, json=dict(CASE_PAYLOAD, case_number="BBB"))
        list1 = client.get("/api/cases", headers=inv1)
        assert list1.status_code == 200
        numbers = [c["case_number"] for c in list1.json()]
        assert numbers == ["AAA"]

    def test_admin_sees_all(self, client, user_factory, login_headers):
        headers = _headers(user_factory, login_headers, "admin", "admA")
        for n in ("AAA", "BBB"):
            client.post("/api/cases", headers=headers, json=dict(CASE_PAYLOAD, case_number=n))
        admin = _headers(user_factory, login_headers, "admin", "admB")
        resp = client.get("/api/cases", headers=admin)
        assert len(resp.json()) == 2


class TestCaseViewIDOR:
    def test_investigator_cannot_view_unassigned_case(self, client, user_factory, login_headers):
        owner_headers = _headers(user_factory, login_headers, "investigator", "ownr")
        created = client.post("/api/cases", headers=owner_headers, json=CASE_PAYLOAD).json()
        other = _headers(user_factory, login_headers, "investigator", "other")
        resp = client.get(f"/api/cases/{created['id']}", headers=other)
        assert resp.status_code == 403

    def test_owner_can_view(self, client, user_factory, login_headers):
        headers = _headers(user_factory, login_headers, "investigator", "owr")
        created = client.post("/api/cases", headers=headers, json=CASE_PAYLOAD).json()
        assert client.get(f"/api/cases/{created['id']}", headers=headers).status_code == 200


class TestCaseUpdateIDOR:
    def test_unassigned_investigator_cannot_update(self, client, user_factory, login_headers):
        owner = _headers(user_factory, login_headers, "investigator", "ownU")
        created = client.post("/api/cases", headers=owner, json=CASE_PAYLOAD).json()
        intruder = _headers(user_factory, login_headers, "investigator", "intr")
        resp = client.patch(
            f"/api/cases/{created['id']}", headers=intruder, json={"status": "closed"}
        )
        assert resp.status_code == 403

    def test_owner_can_update_status(self, client, user_factory, login_headers):
        headers = _headers(user_factory, login_headers, "investigator", "owrU")
        created = client.post("/api/cases", headers=headers, json=CASE_PAYLOAD).json()
        resp = client.patch(
            f"/api/cases/{created['id']}", headers=headers, json={"status": "closed"}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "closed"

    def test_admin_can_update_any(self, client, user_factory, login_headers):
        created_by = _headers(user_factory, login_headers, "investigator", "byI")
        created = client.post("/api/cases", headers=created_by, json=CASE_PAYLOAD).json()
        admin = _headers(user_factory, login_headers, "admin", "admU")
        resp = client.patch(
            f"/api/cases/{created['id']}", headers=admin, json={"title": "Updated"}
        )
        assert resp.status_code == 200
        assert resp.json()["title"] == "Updated"

    def test_unknown_case_404(self, client, user_factory, login_headers):
        headers = _headers(user_factory, login_headers, "investigator", "inv404")
        assert client.get(f"/api/cases/{uuid4()}", headers=headers).status_code == 404