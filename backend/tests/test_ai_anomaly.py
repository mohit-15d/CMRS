"""Stage 17 AI-assisted anomaly detection tests."""

from app.models.ai_alert import AIAlert
from app.models.audit_log import AuditLog
from app.security.audit_ledger import append_audit_event


def _seed_normal_behavior(db_session, user):
    for _ in range(3):
        append_audit_event(db_session, actor_id=user.id, action="LOGIN")
    append_audit_event(
        db_session,
        actor_id=user.id,
        action="EVIDENCE_ACCESSED",
        resource_type="evidence",
        details={"file_size": 100},
    )


def test_normal_behavior_is_labeled_normal(client, user_factory, login_headers, db_session):
    # NOTE (Stage 21 integration fix): this test previously seeded only ONE
    # peer and relied on the live dev database containing almost no other
    # audit activity. IsolationForest fits over ALL committed audit events,
    # so legitimate integration/demo activity in the shared database shifts
    # the population distribution and can flip the label of the "normal"
    # target (observed: ANOMALOUS after Stage-21 e2e runs). The committed
    # audit rows cannot be removed (chained, tamper-evident ledger), so the
    # test now seeds a controlled baseline population large enough to define
    # the "normal" region itself. Assertions are unchanged - the test is
    # hardened, not weakened.
    admin = user_factory(role="admin", username="ai_normal_admin")
    target = user_factory(role="investigator", username="ai_normal_target")
    peers = [
        user_factory(role="investigator", username=f"ai_normal_peer_{index}")
        for index in range(25)
    ]
    for peer in peers:
        _seed_normal_behavior(db_session, peer)
    _seed_normal_behavior(db_session, target)

    response = client.post(
        f"/api/admin/anomaly/users/{target.id}",
        headers=login_headers(admin.username, "Passw0rd!x"),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["label"] == "NORMAL"
    assert isinstance(body["score"], float)
    assert body["advisory"] is True
    assert body["alert_id"] is None


def test_anomalous_behavior_creates_advisory_alert(client, user_factory, login_headers, db_session):
    admin = user_factory(role="admin", username="ai_anomaly_admin")
    target = user_factory(role="investigator", username="ai_anomaly_target")
    peers = [user_factory(role="investigator", username=f"ai_anomaly_peer_{index}") for index in range(5)]
    for peer in peers:
        _seed_normal_behavior(db_session, peer)
    for _ in range(30):
        append_audit_event(db_session, actor_id=target.id, action="LOGIN_FAILURE", result="failure")
        append_audit_event(
            db_session,
            actor_id=target.id,
            action="EVIDENCE_ACCESSED",
            resource_type="evidence",
            details={"file_size": 10_000_000},
        )

    response = client.post(
        f"/api/admin/anomaly/users/{target.id}",
        headers=login_headers(admin.username, "Passw0rd!x"),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["label"] == "ANOMALOUS"
    assert body["alert_id"] is not None
    alert = db_session.get(AIAlert, body["alert_id"])
    assert alert is not None
    assert alert.status == "open"
    assert alert.user_id == target.id
    assert any(row.action == "ALERT_CREATED" for row in db_session.query(AuditLog).all())


def test_insufficient_data_is_reported_without_alert(client, user_factory, login_headers, db_session):
    admin = user_factory(role="admin", username="ai_insufficient_admin")
    target = user_factory(role="investigator", username="ai_insufficient_target")

    response = client.post(
        f"/api/admin/anomaly/users/{target.id}",
        headers=login_headers(admin.username, "Passw0rd!x"),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["label"] == "INSUFFICIENT_DATA"
    assert body["score"] is None
    assert body["alert_id"] is None
    assert db_session.query(AIAlert).filter(AIAlert.user_id == target.id).count() == 0


def test_ai_service_failure_is_safe(monkeypatch, client, user_factory, login_headers, db_session):
    admin = user_factory(role="admin", username="ai_unavailable_admin")
    target = user_factory(role="investigator", username="ai_unavailable_target")
    peer = user_factory(role="investigator", username="ai_unavailable_peer")
    _seed_normal_behavior(db_session, target)
    _seed_normal_behavior(db_session, peer)

    def unavailable(*args, **kwargs):
        raise RuntimeError("detector unavailable")

    monkeypatch.setattr("app.services.anomaly_detection.IsolationForest", unavailable)
    response = client.post(
        f"/api/admin/anomaly/users/{target.id}",
        headers=login_headers(admin.username, "Passw0rd!x"),
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "AI-assisted anomaly analysis is temporarily unavailable"
