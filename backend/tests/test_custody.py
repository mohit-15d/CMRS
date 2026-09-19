"""Stage 14 digital chain-of-custody workflow tests."""

from datetime import datetime
from uuid import uuid4

from app.models.custody_transfer import CustodyTransfer


CASE_PAYLOAD = {
    "case_number": "CASE-CUSTODY-1",
    "title": "Custody test",
    "description": "Chain of custody test",
    "offense": "Theft",
    "victim": "ACME",
    "suspect": "Unknown",
    "submitting_officer": "Det. Jones",
    "location": "Warehouse",
    "status": "open",
}


def _create_evidence(client, investigator, login_headers, user_factory, suffix):
    headers = login_headers(investigator.username, "Passw0rd!x")
    case = client.post(
        "/api/cases",
        headers=headers,
        json={**CASE_PAYLOAD, "case_number": f"CASE-CUSTODY-{suffix}"},
    )
    assert case.status_code == 201, case.text
    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case.json()["id"], "item_number": "7", "description": "Custody test"},
        files={"file": ("custody.bin", b"custody evidence", "application/octet-stream")},
    )
    assert upload.status_code == 201, upload.text
    return upload.json(), headers


def test_valid_transfer_records_authenticated_custody_event(client, user_factory, login_headers):
    investigator = user_factory(role="investigator", username="custody_owner")
    recipient = user_factory(role="investigator", username="custody_recipient")
    evidence, headers = _create_evidence(client, investigator, login_headers, user_factory, "VALID")

    response = client.post(
        f"/api/evidence/{evidence['id']}/custody",
        headers=headers,
        json={
            "received_by_id": str(recipient.id),
            "action": "transferred",
            "comments": "Transferred for forensic examination",
            "location": "Forensics lab",
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["evidence_id"] == evidence["id"]
    assert body["item_number"] == 7
    assert body["released_by"] == investigator.username
    assert body["received_by"] == recipient.username
    assert body["authenticated_user"] == investigator.username
    assert body["action"] == "transferred"
    assert body["purpose"] == "Transferred for forensic examination"
    assert body["location"] == "Forensics lab"


def test_unauthorized_user_cannot_transfer_evidence(client, user_factory, login_headers):
    owner = user_factory(role="investigator", username="custody_owner_unauth")
    recipient = user_factory(role="investigator", username="custody_recipient_unauth")
    other = user_factory(role="investigator", username="custody_other")
    evidence, _ = _create_evidence(client, owner, login_headers, user_factory, "UNAUTH")

    response = client.post(
        f"/api/evidence/{evidence['id']}/custody",
        headers=login_headers(other.username, "Passw0rd!x"),
        json={"received_by_id": str(recipient.id), "comments": "Unauthorized"},
    )

    assert response.status_code == 403


def test_invalid_recipient_is_rejected(client, user_factory, login_headers):
    owner = user_factory(role="investigator", username="custody_owner_invalid")
    evidence, headers = _create_evidence(client, owner, login_headers, user_factory, "INVALID")

    response = client.post(
        f"/api/evidence/{evidence['id']}/custody",
        headers=headers,
        json={"received_by_id": str(uuid4()), "comments": "Missing recipient"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid custody recipient"


def test_missing_evidence_is_rejected(client, user_factory, login_headers):
    investigator = user_factory(role="investigator", username="custody_missing")
    recipient = user_factory(role="investigator", username="custody_missing_recipient")
    response = client.post(
        f"/api/evidence/{uuid4()}/custody",
        headers=login_headers(investigator.username, "Passw0rd!x"),
        json={"received_by_id": str(recipient.id)},
    )
    assert response.status_code == 404


def test_custody_history_is_chronological_and_append_only(client, user_factory, login_headers):
    owner = user_factory(role="investigator", username="custody_chrono_owner")
    recipient = user_factory(role="investigator", username="custody_chrono_recipient")
    final_recipient = user_factory(role="investigator", username="custody_chrono_final")
    evidence, headers = _create_evidence(client, owner, login_headers, user_factory, "CHRONO")

    first = client.post(
        f"/api/evidence/{evidence['id']}/custody",
        headers=headers,
        json={"received_by_id": str(recipient.id), "action": "received", "comments": "Received"},
    )
    second = client.post(
        f"/api/evidence/{evidence['id']}/custody",
        headers=login_headers(recipient.username, "Passw0rd!x"),
        json={"received_by_id": str(final_recipient.id), "action": "examined", "comments": "Examined"},
    )
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text

    history = client.get(f"/api/evidence/{evidence['id']}/custody", headers=headers)
    assert history.status_code == 200, history.text
    events = history.json()
    assert [event["action"] for event in events] == ["created", "received", "examined"]
    dates = [datetime.fromisoformat(event["transferred_at"]) for event in events]
    assert dates == sorted(dates)
    assert all("delete" not in event and "updated_at" not in event for event in events)


def test_viewer_cannot_read_or_append_custody_history(client, user_factory, login_headers):
    owner = user_factory(role="investigator", username="custody_view_owner")
    viewer = user_factory(role="viewer", username="custody_viewer")
    evidence, _ = _create_evidence(client, owner, login_headers, user_factory, "VIEW")
    viewer_headers = login_headers(viewer.username, "Passw0rd!x")

    read_response = client.get(f"/api/evidence/{evidence['id']}/custody", headers=viewer_headers)
    write_response = client.post(
        f"/api/evidence/{evidence['id']}/custody",
        headers=viewer_headers,
        json={"received_by_id": str(owner.id)},
    )
    assert read_response.status_code == 403
    assert write_response.status_code == 403


# ---------------------------------------------------------------------------
# Custody recipient dropdown endpoint (GET /api/custody/recipients) and
# received_by_id parameter-tampering guards.
# ---------------------------------------------------------------------------


def test_recipient_list_requires_authentication(client):
    assert client.get("/api/custody/recipients").status_code == 401


def test_recipient_list_forbidden_for_viewer(client, user_factory, login_headers):
    user_factory(role="viewer", username="recip_viewer")
    resp = client.get(
        "/api/custody/recipients",
        headers=login_headers("recip_viewer", "Passw0rd!x"),
    )
    assert resp.status_code == 403


def test_recipient_list_returns_only_active_managers(
    client, user_factory, login_headers, db_session
):
    user_factory(role="investigator", username="recip_caller")
    user_factory(role="investigator", username="recip_inv")
    user_factory(role="admin", username="recip_admin")
    user_factory(role="viewer", username="recip_hidden_viewer")
    inactive = user_factory(role="investigator", username="recip_hidden_inactive")
    inactive.is_active = False
    db_session.flush()

    resp = client.get(
        "/api/custody/recipients",
        headers=login_headers("recip_caller", "Passw0rd!x"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    usernames = [u["username"] for u in body]
    assert "recip_inv" in usernames
    assert "recip_admin" in usernames
    assert "recip_hidden_viewer" not in usernames
    assert "recip_hidden_inactive" not in usernames
    # Safe fields only (no email, full_name, is_active or anything sensitive).
    assert all(set(u.keys()) == {"id", "username", "role"} for u in body)
    # Ordered by username for a stable dropdown.
    assert usernames == sorted(usernames)


def test_tampered_recipient_viewer_is_rejected(client, user_factory, login_headers):
    owner = user_factory(role="investigator", username="tamper_owner")
    viewer = user_factory(role="viewer", username="tamper_viewer")
    evidence, headers = _create_evidence(
        client, owner, login_headers, user_factory, "TAMPER1"
    )
    resp = client.post(
        f"/api/evidence/{evidence['id']}/custody",
        headers=headers,
        json={"received_by_id": str(viewer.id), "action": "transferred"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid custody recipient"


def test_tampered_recipient_inactive_is_rejected(
    client, user_factory, login_headers, db_session
):
    owner = user_factory(role="investigator", username="tamper_owner2")
    inactive = user_factory(role="investigator", username="tamper_inactive")
    inactive.is_active = False
    db_session.flush()
    evidence, headers = _create_evidence(
        client, owner, login_headers, user_factory, "TAMPER2"
    )
    resp = client.post(
        f"/api/evidence/{evidence['id']}/custody",
        headers=headers,
        json={"received_by_id": str(inactive.id), "action": "transferred"},
    )
    assert resp.status_code == 400
