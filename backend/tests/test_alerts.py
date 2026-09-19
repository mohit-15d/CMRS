"""Stage 18 security alerts tests.

Covers alert creation, listing, retrieval, authorization, review/resolution,
and the built-in alert triggers (integrity mismatch, excessive failed logins,
AI anomaly, audit-chain failure), including deduplication of open alerts.
"""

import uuid
from pathlib import Path

from app.models.ai_alert import (
    AIAlert,
    ALERT_TYPE_AUDIT_LEDGER_INVALID,
    ALERT_TYPE_EXCESSIVE_FAILED_LOGINS,
    ALERT_TYPE_INTEGRITY_MISMATCH,
)
from app.models.audit_log import AuditLog
from app.security.audit_ledger import append_audit_event
from app.security.encryption import encrypt_evidence
from app.services.alerts import create_alert

CASE_PAYLOAD = {
    "case_number": "CASE-ALERTS-1",
    "title": "Security alerts test",
    "description": "Stage 18 alert triggers",
    "offense": "Test",
    "victim": "Test",
    "suspect": "Test",
    "submitting_officer": "Test",
    "location": "Test",
    "status": "open",
}


def _create_case(client, headers, case_number):
    resp = client.post(
        "/api/cases", headers=headers,
        json=dict(CASE_PAYLOAD, case_number=case_number),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _upload_evidence(client, headers, case_id, filename="alerts.bin", content=b"alert evidence"):
    resp = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Alert test evidence"},
        files={"file": (filename, content, "application/octet-stream")},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# --------------------------------------------------------------------------
# Service-level creation, ledger auditability, deduplication
# --------------------------------------------------------------------------

class TestAlertCreation:
    def test_create_alert_writes_alert_and_audit_event(self, db_session, user_factory):
        actor = user_factory(role="investigator", username="alerts_svc_actor")
        alert = create_alert(
            db_session,
            alert_type="integrity_mismatch",
            severity="high",
            explanation="Test alert",
            user_id=actor.id,
            actor_id=actor.id,
            details={"key": "value"},
        )
        assert alert.id is not None
        assert alert.status == "open"
        stored = db_session.get(AIAlert, alert.id)
        assert stored is not None
        assert stored.alert_type == "integrity_mismatch"
        assert any(row.action == "ALERT_CREATED" for row in db_session.query(AuditLog).all())

    def test_dedupe_returns_existing_open_alert(self, db_session, user_factory):
        actor = user_factory(role="investigator", username="alerts_svc_dedupe")
        dedupe = {"alert_type": "integrity_mismatch", "user_id": actor.id}
        first = create_alert(
            db_session, alert_type="integrity_mismatch", severity="high",
            explanation="One", user_id=actor.id, dedupe=dedupe,
        )
        second = create_alert(
            db_session, alert_type="integrity_mismatch", severity="high",
            explanation="Two", user_id=actor.id, dedupe=dedupe,
        )
        assert second.id == first.id
        assert db_session.query(AIAlert).filter(
            AIAlert.alert_type == "integrity_mismatch",
            AIAlert.user_id == actor.id,
        ).count() == 1


# --------------------------------------------------------------------------
# API authorization (backend enforced, not UI hiding)
# --------------------------------------------------------------------------

class TestAlertAuthorization:
    def test_list_requires_auth(self, client):
        assert client.get("/api/admin/alerts").status_code == 401

    def test_list_forbidden_for_investigator(self, client, user_factory, login_headers):
        investigator = user_factory(role="investigator", username="alerts_unauth_inv")
        headers = login_headers(investigator.username, "Passw0rd!x")
        assert client.get("/api/admin/alerts", headers=headers).status_code == 403

    def test_list_forbidden_for_viewer(self, client, user_factory, login_headers):
        viewer = user_factory(role="viewer", username="alerts_unauth_view")
        headers = login_headers(viewer.username, "Passw0rd!x")
        assert client.get("/api/admin/alerts", headers=headers).status_code == 403

    def test_review_forbidden_for_investigator(self, client, user_factory, login_headers, db_session):
        admin = user_factory(role="admin", username="alerts_admin_seed")
        alert = create_alert(
            db_session, alert_type="behavioral_anomaly", severity="medium",
            explanation="Seed", actor_id=admin.id,
        )
        investigator = user_factory(role="investigator", username="alerts_unauth_review")
        headers = login_headers(investigator.username, "Passw0rd!x")
        resp = client.patch(
            f"/api/admin/alerts/{alert.id}/review",
            headers=headers,
            json={"status": "reviewed"},
        )
        assert resp.status_code == 403

# --------------------------------------------------------------------------
# Listing and retrieval
# --------------------------------------------------------------------------

class TestAlertListAndGet:
    def test_list_and_filter(self, client, user_factory, login_headers, db_session):
        admin = user_factory(role="admin", username="alerts_list_admin")
        actor = user_factory(role="investigator", username="alerts_list_target")
        create_alert(
            db_session, alert_type="behavioral_anomaly", severity="medium",
            explanation="Anomaly alert", user_id=actor.id, actor_id=admin.id,
        )
        create_alert(
            db_session, alert_type="excessive_failed_logins", severity="high",
            explanation="Lockout", user_id=actor.id, actor_id=admin.id,
        )
        headers = login_headers(admin.username, "Passw0rd!x")

        listed = client.get("/api/admin/alerts", headers=headers).json()
        assert len(listed) == 2
        assert {a["alert_type"] for a in listed} == {
            "behavioral_anomaly",
            "excessive_failed_logins",
        }

        filtered = client.get(
            "/api/admin/alerts", headers=headers, params={"status": "open"}
        ).json()
        assert len(filtered) == 2
        assert filtered[0]["status"] == "open"
        assert filtered[0]["reviewed_by"] is None
        assert filtered[0]["severity"] in {"medium", "high"}

    def test_get_by_id_and_404(self, client, user_factory, login_headers, db_session):
        admin = user_factory(role="admin", username="alerts_get_admin")
        alert = create_alert(
            db_session, alert_type="evidence_not_found", severity="high",
            explanation="Missing", actor_id=admin.id,
        )
        headers = login_headers(admin.username, "Passw0rd!x")
        body = client.get(f"/api/admin/alerts/{alert.id}", headers=headers).json()
        assert body["id"] == str(alert.id)
        assert body["alert_type"] == "evidence_not_found"
        assert body["status"] == "open"
        assert (
            client.get(f"/api/admin/alerts/{uuid.uuid4()}", headers=headers).status_code
            == 404
        )

    def test_invalid_status_filter_422(self, client, user_factory, login_headers):
        admin = user_factory(role="admin", username="alerts_filter_admin")
        headers = login_headers(admin.username, "Passw0rd!x")
        assert (
            client.get(
                "/api/admin/alerts", headers=headers, params={"status": "banished"}
            ).status_code
            == 422
        )


# --------------------------------------------------------------------------
# Review / resolve / dismiss
# --------------------------------------------------------------------------

class TestAlertReview:
    def _seed(self, db_session, admin):
        return create_alert(
            db_session, alert_type="behavioral_anomaly", severity="medium",
            explanation="Review me", actor_id=admin.id,
        )

    def test_reviewed_sets_reviewer(self, client, user_factory, login_headers, db_session):
        admin = user_factory(role="admin", username="alerts_rev_admin")
        alert = self._seed(db_session, admin)
        headers = login_headers(admin.username, "Passw0rd!x")
        body = client.patch(
            f"/api/admin/alerts/{alert.id}/review",
            headers=headers,
            json={"status": "reviewed"},
        ).json()
        assert body["status"] == "reviewed"
        assert body["reviewed_by"] == admin.username
        assert body["reviewed_by_id"] == str(admin.id)
        assert body["reviewed_at"] is not None
        assert body["resolved_at"] is None

    def test_resolve_sets_resolution(self, client, user_factory, login_headers, db_session):
        admin = user_factory(role="admin", username="alerts_res_admin")
        alert = self._seed(db_session, admin)
        headers = login_headers(admin.username, "Passw0rd!x")
        body = client.patch(
            f"/api/admin/alerts/{alert.id}/review",
            headers=headers,
            json={"status": "resolved", "resolution": "Verified no malicious action."},
        ).json()
        assert body["status"] == "resolved"
        assert body["resolution"] == "Verified no malicious action."
        assert body["resolved_at"] is not None
        assert body["reviewed_at"] is not None
        assert any(row.action == "ALERT_REVIEWED" for row in db_session.query(AuditLog).all())

    def test_dismiss(self, client, user_factory, login_headers, db_session):
        admin = user_factory(role="admin", username="alerts_dis_admin")
        alert = self._seed(db_session, admin)
        headers = login_headers(admin.username, "Passw0rd!x")
        body = client.patch(
            f"/api/admin/alerts/{alert.id}/review",
            headers=headers,
            json={"status": "dismissed"},
        ).json()
        assert body["status"] == "dismissed"
        assert body["resolved_at"] is not None

    def test_invalid_status_422(self, client, user_factory, login_headers, db_session):
        admin = user_factory(role="admin", username="alerts_bad_admin")
        alert = self._seed(db_session, admin)
        headers = login_headers(admin.username, "Passw0rd!x")
        resp = client.patch(
            f"/api/admin/alerts/{alert.id}/review",
            headers=headers,
            json={"status": "deleted"},
        )
        assert resp.status_code == 422

    def test_review_unknown_alert_404(self, client, user_factory, login_headers):
        admin = user_factory(role="admin", username="alerts_404_admin")
        headers = login_headers(admin.username, "Passw0rd!x")
        resp = client.patch(
            f"/api/admin/alerts/{uuid.uuid4()}/review",
            headers=headers,
            json={"status": "resolved"},
        )
        assert resp.status_code == 404

# --------------------------------------------------------------------------
# Event triggers (integrated via real endpoints)
# --------------------------------------------------------------------------

def test_integrity_mismatch_creates_alert(client, user_factory, login_headers, db_session):
    investigator = user_factory(role="investigator", username="alerts_inv_integ")
    headers = login_headers(investigator.username, "Passw0rd!x")
    case_id = _create_case(client, headers, "CASE-ALERTS-INTEG")
    evidence = _upload_evidence(client, headers, case_id, content=b"original data")
    Path(evidence["storage_path"]).write_bytes(encrypt_evidence(b"tampered data"))

    resp = client.post(f"/api/evidence/verify/{evidence['id']}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["match"] is False
    assert resp.json()["status"] == "INTEGRITY VIOLATION"

    alerts = db_session.query(AIAlert).filter(
        AIAlert.alert_type == ALERT_TYPE_INTEGRITY_MISMATCH
    ).all()
    assert len(alerts) == 1
    assert alerts[0].evidence_id == uuid.UUID(evidence["id"])
    assert alerts[0].severity == "critical"

    # Repeated verification of the same corrupt file must not re-create the alert.
    client.post(f"/api/evidence/verify/{evidence['id']}", headers=headers)
    assert db_session.query(AIAlert).filter(
        AIAlert.alert_type == ALERT_TYPE_INTEGRITY_MISMATCH
    ).count() == 1


def test_missing_evidence_creates_alert(client, user_factory, login_headers, db_session):
    investigator = user_factory(role="investigator", username="alerts_inv_miss")
    headers = login_headers(investigator.username, "Passw0rd!x")
    case_id = _create_case(client, headers, "CASE-ALERTS-MISS")
    evidence = _upload_evidence(client, headers, case_id)
    Path(evidence["storage_path"]).unlink()

    assert client.post(f"/api/evidence/verify/{evidence['id']}", headers=headers).status_code == 410
    alerts = db_session.query(AIAlert).filter(
        AIAlert.alert_type == "evidence_not_found"
    ).all()
    assert len(alerts) == 1
    assert alerts[0].evidence_id == uuid.UUID(evidence["id"])


def test_excessive_failed_logins_creates_alert(client, user_factory, login_headers, db_session):
    admin = user_factory(role="admin", username="alerts_adm_lockout")
    target = user_factory(role="viewer", username="alerts_lock_target")
    login_headers(admin.username, "Passw0rd!x")

    for _ in range(5):
        assert (
            client.post(
                "/api/auth/login",
                json={"username": target.username, "password": "Wrong-1"},
            ).status_code
            == 401
        )
    blocked = client.post(
        "/api/auth/login", json={"username": target.username, "password": "Wrong-1"}
    )
    assert blocked.status_code == 429

    alerts = db_session.query(AIAlert).filter(
        AIAlert.alert_type == ALERT_TYPE_EXCESSIVE_FAILED_LOGINS
    ).all()
    assert len(alerts) == 1
    assert alerts[0].user_id == target.id
    assert alerts[0].severity == "high"


def test_ai_anomaly_creates_alert(client, user_factory, login_headers, db_session):
    admin = user_factory(role="admin", username="alerts_ai_admin")
    target = user_factory(role="investigator", username="alerts_ai_target")
    for index in range(5):
        peer = user_factory(role="investigator", username=f"alerts_ai_peer_{index}")
        for _ in range(3):
            append_audit_event(db_session, actor_id=peer.id, action="LOGIN")
    for _ in range(30):
        append_audit_event(db_session, actor_id=target.id, action="LOGIN_FAILURE", result="failure")
        append_audit_event(
            db_session,
            actor_id=target.id,
            action="EVIDENCE_ACCESSED",
            resource_type="evidence",
            details={"file_size": 10_000_000},
        )

    headers = login_headers(admin.username, "Passw0rd!x")
    resp = client.post(f"/api/admin/anomaly/users/{target.id}", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["label"] == "ANOMALOUS"
    assert body["alert_id"] is not None

    listed = client.get("/api/admin/alerts", headers=headers).json()
    assert any(
        a["id"] == str(body["alert_id"]) and a["alert_type"] == "behavioral_anomaly"
        for a in listed
    )


def test_audit_chain_failure_creates_alert_and_dedupes(
    client, user_factory, login_headers, db_session
):
    admin = user_factory(role="admin", username="alerts_ledger_admin")
    record = append_audit_event(db_session, actor_id=admin.id, action="TEST_ALERT_LEDGER")
    record.current_hash = "0" * 64  # simulate tampering
    headers = login_headers(admin.username, "Passw0rd!x")

    first = client.post("/api/admin/audit-ledger/verify", headers=headers)
    assert first.status_code == 200
    assert first.json()["valid"] is False
    assert first.json()["status"] == "AUDIT CHAIN INVALID"

    alerts = db_session.query(AIAlert).filter(
        AIAlert.alert_type == ALERT_TYPE_AUDIT_LEDGER_INVALID
    ).all()
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"

    # Verifying again must not create a second open alert.
    client.post("/api/admin/audit-ledger/verify", headers=headers)
    assert db_session.query(AIAlert).filter(
        AIAlert.alert_type == ALERT_TYPE_AUDIT_LEDGER_INVALID
    ).count() == 1