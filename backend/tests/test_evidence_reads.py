"""Read-endpoint tests added for Stage 20 (evidence list/detail, audit logs).

These endpoints back the React frontend pages (Evidence, Evidence Details,
Audit Ledger). All authorization is enforced server-side; these tests verify
that the frontend cannot rely on role-hiding alone.
"""

import uuid

CASE_PAYLOAD = {
    "case_number": "CASE-READS-1",
    "title": "Read endpoint tests",
    "description": "Stage 20 read endpoints",
    "offense": "Fraud",
    "victim": "Victim Co",
    "suspect": "Unknown",
    "submitting_officer": "Det. Read",
    "location": "Lab",
    "status": "open",
}


def _make_case_with_evidence(client, user_factory, login_headers, username, case_number):
    """Create a case + one uploaded evidence item; return (case_id, evidence_id)."""
    user_factory(role="investigator", username=username)
    headers = login_headers(username, "Passw0rd!x")
    case = client.post(
        "/api/cases", headers=headers, json=dict(CASE_PAYLOAD, case_number=case_number)
    )
    assert case.status_code == 201, case.text
    case_id = case.json()["id"]
    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "item_number": "1", "description": "USB drive"},
        files={"file": ("disk.img", b"stage20-evidence-bytes", "application/octet-stream")},
    )
    assert upload.status_code == 201, upload.text
    return case_id, upload.json()["id"]


class TestEvidenceList:
    def test_investigator_lists_own_case_evidence(self, client, user_factory, login_headers):
        _, evidence_id = _make_case_with_evidence(
            client, user_factory, login_headers, "inv_list1", "CASE-READS-L1"
        )
        resp = client.get(
            "/api/evidence", headers=login_headers("inv_list1", "Passw0rd!x")
        )
        assert resp.status_code == 200
        ids = [item["id"] for item in resp.json()]
        assert evidence_id in ids

    def test_investigator_cannot_list_other_cases_evidence(
        self, client, user_factory, login_headers
    ):
        _make_case_with_evidence(
            client, user_factory, login_headers, "inv_list_owner", "CASE-READS-L2"
        )
        user_factory(role="investigator", username="inv_list_other")
        resp = client.get(
            "/api/evidence", headers=login_headers("inv_list_other", "Passw0rd!x")
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_case_filter_for_unauthorized_case_is_403(
        self, client, user_factory, login_headers
    ):
        case_id, _ = _make_case_with_evidence(
            client, user_factory, login_headers, "inv_list_owner2", "CASE-READS-L3"
        )
        user_factory(role="investigator", username="inv_list_outsider")
        resp = client.get(
            f"/api/evidence?case_id={case_id}",
            headers=login_headers("inv_list_outsider", "Passw0rd!x"),
        )
        assert resp.status_code == 403

    def test_list_requires_authentication(self, client):
        assert client.get("/api/evidence").status_code == 401


class TestEvidenceDetail:
    def test_detail_includes_original_hash_and_verification(
        self, client, user_factory, login_headers
    ):
        case_id, evidence_id = _make_case_with_evidence(
            client, user_factory, login_headers, "inv_detail", "CASE-READS-D1"
        )
        headers = login_headers("inv_detail", "Passw0rd!x")

        before = client.get(f"/api/evidence/{evidence_id}", headers=headers)
        assert before.status_code == 200
        body = before.json()
        assert body["original_hash"]["hash_type"] == "original"
        assert len(body["original_hash"]["sha256_hex"]) == 64
        assert body["latest_verification"] is None
        assert body["uploaded_by"] == "inv_detail"

        verify = client.post(f"/api/evidence/verify/{evidence_id}", headers=headers)
        assert verify.status_code == 200

        after = client.get(f"/api/evidence/{evidence_id}", headers=headers)
        latest = after.json()["latest_verification"]
        assert latest is not None
        assert latest["hash_type"] == "verification"
        assert latest["match_result"] is True

    def test_detail_404_unknown(self, client, user_factory, login_headers):
        user_factory(role="admin", username="admin_detail404")
        headers = login_headers("admin_detail404", "Passw0rd!x")
        assert (
            client.get(f"/api/evidence/{uuid.uuid4()}", headers=headers).status_code
            == 404
        )

    def test_detail_forbidden_for_outsider_investigator(
        self, client, user_factory, login_headers
    ):
        _, evidence_id = _make_case_with_evidence(
            client, user_factory, login_headers, "inv_detail_owner", "CASE-READS-D2"
        )
        user_factory(role="investigator", username="inv_detail_outsider")
        resp = client.get(
            f"/api/evidence/{evidence_id}",
            headers=login_headers("inv_detail_outsider", "Passw0rd!x"),
        )
        assert resp.status_code == 403


class TestAuditLogListing:
    def test_admin_can_list_audit_logs(self, client, user_factory, login_headers):
        user_factory(role="admin", username="admin_logs")
        headers = login_headers("admin_logs", "Passw0rd!x")
        # Logging in itself audits a LOGIN event; create another audited action.
        client.post(
            "/api/cases",
            headers=headers,
            json=dict(CASE_PAYLOAD, case_number="CASE-READS-A1"),
        )
        resp = client.get("/api/admin/audit-logs", headers=headers)
        assert resp.status_code == 200
        logs = resp.json()
        assert len(logs) >= 2
        actions = {log["action"] for log in logs}
        assert "LOGIN" in actions and "CASE_CREATED" in actions
        case_log = next(log for log in logs if log["action"] == "CASE_CREATED")
        assert case_log["actor_username"] == "admin_logs"
        assert case_log["resource_type"] == "case"

    def test_action_filter_and_limit(self, client, user_factory, login_headers):
        user_factory(role="admin", username="admin_logs_filter")
        headers = login_headers("admin_logs_filter", "Passw0rd!x")
        resp = client.get("/api/admin/audit-logs?action=LOGIN&limit=2", headers=headers)
        assert resp.status_code == 200
        logs = resp.json()
        assert len(logs) <= 2
        assert all(log["action"] == "LOGIN" for log in logs)

    def test_investigator_forbidden(self, client, user_factory, login_headers):
        user_factory(role="investigator", username="inv_logs")
        resp = client.get(
            "/api/admin/audit-logs", headers=login_headers("inv_logs", "Passw0rd!x")
        )
        assert resp.status_code == 403

    def test_unauthenticated_unauthorized(self, client):
        assert client.get("/api/admin/audit-logs").status_code == 401

