"""Stage 16 chained audit ledger and security event tests."""

from app.models.audit_log import AuditLog
from app.security.audit_ledger import GENESIS_HASH, append_audit_event, verify_audit_chain


def test_empty_chain_is_valid_and_first_record_uses_genesis(db_session, user_factory):
    """A new record links to the current head (genesis when the ledger is empty).

    The shared dev database may already contain committed rows from live
    sessions, so we assert the record links to whatever the head is at the
    moment of append; when the ledger is empty that head is the genesis hash.
    """
    actor = user_factory(role="investigator", username="ledger_genesis")
    valid, error = verify_audit_chain(db_session)
    assert valid is True
    assert error is None

    head = db_session.query(AuditLog).order_by(
        AuditLog.created_at.desc(), AuditLog.id.desc()
    ).first()
    expected_previous = head.current_hash if head else GENESIS_HASH

    record = append_audit_event(db_session, actor_id=actor.id, action="TEST_GENESIS")
    assert record.previous_hash == expected_previous
    valid, error = verify_audit_chain(db_session)
    assert valid is True
    assert error is None


def test_valid_chain_verifies(db_session, user_factory):
    actor = user_factory(role="investigator", username="ledger_valid")
    first = append_audit_event(db_session, actor_id=actor.id, action="TEST_ONE")
    second = append_audit_event(db_session, actor_id=actor.id, action="TEST_TWO")
    assert second.previous_hash == first.current_hash
    valid, error = verify_audit_chain(db_session)
    assert valid is True
    assert error is None


def test_altered_record_is_invalid_and_not_repaired(db_session, user_factory):
    actor = user_factory(role="investigator", username="ledger_altered")
    record = append_audit_event(db_session, actor_id=actor.id, action="TEST_ALTER", details={"safe": "value"})
    original_hash = record.current_hash
    record.details = {"safe": "changed"}
    valid, error = verify_audit_chain(db_session)
    assert valid is False
    assert "Invalid hash" in error
    assert record.current_hash == original_hash


def test_altered_previous_hash_is_invalid(db_session, user_factory):
    actor = user_factory(role="investigator", username="ledger_previous")
    record = append_audit_event(db_session, actor_id=actor.id, action="TEST_PREVIOUS")
    record.previous_hash = "0" * 64
    valid, error = verify_audit_chain(db_session)
    assert valid is False
    assert "Broken link" in error


def test_broken_chain_is_invalid(db_session, user_factory):
    actor = user_factory(role="investigator", username="ledger_broken")
    append_audit_event(db_session, actor_id=actor.id, action="TEST_FIRST")
    second = append_audit_event(db_session, actor_id=actor.id, action="TEST_SECOND")
    second.previous_hash = "f" * 64
    valid, error = verify_audit_chain(db_session)
    assert valid is False
    assert error is not None


def test_ledger_verification_requires_admin(client, user_factory, login_headers):
    investigator = user_factory(role="investigator", username="ledger_nonadmin")
    headers = login_headers(investigator.username, "Passw0rd!x")
    response = client.post("/api/admin/audit-ledger/verify", headers=headers)
    assert response.status_code == 403


def test_ledger_verification_endpoint_reports_valid_chain(client, user_factory, login_headers):
    admin = user_factory(role="admin", username="ledger_admin")
    headers = login_headers(admin.username, "Passw0rd!x")
    response = client.post("/api/admin/audit-ledger/verify", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["valid"] is True
    assert body["status"] == "AUDIT CHAIN VALID"
    assert body["checked_records"] >= 1


def test_ledger_verification_endpoint_reports_corruption_without_repair(
    client, user_factory, login_headers, db_session
):
    admin = user_factory(role="admin", username="ledger_corrupt_admin")
    headers = login_headers(admin.username, "Passw0rd!x")
    record = db_session.query(AuditLog).order_by(AuditLog.created_at, AuditLog.id).first()
    original_hash = record.current_hash
    record.current_hash = "0" * 64

    response = client.post("/api/admin/audit-ledger/verify", headers=headers)

    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["status"] == "AUDIT CHAIN INVALID"
    assert record.current_hash == "0" * 64
    assert record.current_hash != original_hash


def test_security_operations_create_standard_audit_events(client, user_factory, login_headers, db_session):
    investigator = user_factory(role="investigator", username="audit_events_owner")
    recipient = user_factory(role="investigator", username="audit_events_recipient")
    headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=headers,
        json={
            "case_number": "CASE-AUDIT-EVENTS",
            "title": "Audit events",
            "description": "Audit event coverage",
            "offense": "Test",
            "victim": "Test",
            "suspect": "Test",
            "submitting_officer": "Test",
            "location": "Test",
            "status": "open",
        },
    )
    assert case.status_code == 201, case.text
    case_id = case.json()["id"]
    update = client.patch(f"/api/cases/{case_id}", headers=headers, json={"title": "Updated audit events"})
    assert update.status_code == 200, update.text

    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Audit evidence"},
        files={"file": ("audit.bin", b"audit evidence", "application/octet-stream")},
    )
    assert upload.status_code == 201, upload.text
    evidence_id = upload.json()["id"]
    verified = client.post(f"/api/evidence/verify/{evidence_id}", headers=headers)
    assert verified.status_code == 200, verified.text

    transfer = client.post(
        f"/api/evidence/{evidence_id}/custody",
        headers=headers,
        json={"received_by_id": str(recipient.id), "action": "transferred"},
    )
    assert transfer.status_code == 201, transfer.text

    actions = {
        row.action
        for row in db_session.query(AuditLog).all()
    }
    assert {"LOGIN", "CASE_CREATED", "CASE_UPDATED", "EVIDENCE_UPLOADED", "EVIDENCE_ACCESSED", "INTEGRITY_CHECK", "CUSTODY_TRANSFER"} <= actions
    assert all(row.previous_hash and row.current_hash for row in db_session.query(AuditLog).all())


def test_login_failure_and_logout_are_audited(client, user_factory, login_headers, db_session):
    user = user_factory(role="investigator", username="audit_login_events")
    failed = client.post("/api/auth/login", json={"username": user.username, "password": "wrong-password"})
    assert failed.status_code == 401
    headers = login_headers(user.username, "Passw0rd!x")
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    actions = {row.action for row in db_session.query(AuditLog).all()}
    assert {"LOGIN_FAILURE", "LOGIN", "LOGOUT"} <= actions


def test_role_change_and_disable_are_audited(client, user_factory, login_headers, db_session):
    admin = user_factory(role="admin", username="audit_admin_events")
    target = user_factory(role="viewer", username="audit_target_events")
    headers = login_headers(admin.username, "Passw0rd!x")
    changed = client.patch(f"/api/admin/users/{target.id}", headers=headers, json={"role": "investigator"})
    disabled = client.patch(f"/api/admin/users/{target.id}", headers=headers, json={"is_active": False})
    assert changed.status_code == 200
    assert disabled.status_code == 200
    actions = {row.action for row in db_session.query(AuditLog).all()}
    assert {"USER_ROLE_CHANGED", "USER_DISABLED"} <= actions
