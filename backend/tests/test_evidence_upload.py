"""Evidence upload tests for Stage 10."""

from pathlib import Path


CASE_PAYLOAD = {
    "case_number": "CASE-UPLOAD-1",
    "title": "Evidence handling",
    "description": "Upload test case",
    "offense": "Theft",
    "victim": "ACME",
    "suspect": "Unknown",
    "submitting_officer": "Det. Smith",
    "location": "Warehouse",
    "status": "open",
}


def _login_case_headers(client, user_factory, login_headers, role, username):
    user = user_factory(role=role, username=username)
    return client.post(
        "/api/cases",
        headers=login_headers(user.username, "Passw0rd!x"),
        json=CASE_PAYLOAD,
    )


def test_viewer_cannot_upload_evidence(client, user_factory, login_headers):
    viewer = user_factory(role="viewer", username="viewer_upload")
    case = client.post(
        "/api/cases",
        headers=login_headers("viewer_upload", "Passw0rd!x"),
        json=CASE_PAYLOAD,
    )
    assert case.status_code == 403

    investigator = user_factory(role="investigator", username="inv_upload")
    created = client.post(
        "/api/cases",
        headers=login_headers(investigator.username, "Passw0rd!x"),
        json=dict(CASE_PAYLOAD, case_number="CASE-UPLOAD-2"),
    )
    assert created.status_code == 201
    case_id = created.json()["id"]

    resp = client.post(
        "/api/evidence/upload",
        headers=login_headers(viewer.username, "Passw0rd!x"),
        data={"case_id": case_id, "item_number": "1", "description": "Unauthorized upload"},
        files={"file": ("sample.bin", b"abc123", "application/octet-stream")},
    )
    assert resp.status_code == 403


def test_invalid_file_rejected(client, user_factory, login_headers):
    investigator = user_factory(role="investigator", username="inv_invalid")
    headers = login_headers(investigator.username, "Passw0rd!x")
    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-UPLOAD-INVALID"),
    )
    assert case.status_code == 201
    case_id = case.json()["id"]

    resp = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Empty file"},
        files={"file": ("empty.bin", b"", "application/octet-stream")},
    )
    assert resp.status_code == 400


def test_oversized_file_rejected(client, user_factory, login_headers):
    investigator = user_factory(role="investigator", username="inv_large")
    headers = login_headers(investigator.username, "Passw0rd!x")
    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-UPLOAD-LARGE"),
    )
    case_id = case.json()["id"]

    resp = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "too large"},
        files={"file": ("large.bin", b"x" * (25 * 1024 * 1024 + 1), "application/octet-stream")},
    )
    assert resp.status_code == 413


def test_investigator_uploads_evidence_to_own_case(client, user_factory, login_headers):
    investigator = user_factory(role="investigator", username="inv_uploader")
    headers = login_headers(investigator.username, "Passw0rd!x")
    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-UPLOAD-3"),
    )
    assert case.status_code == 201
    case_id = case.json()["id"]

    resp = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "item_number": "1", "description": "Laptop image"},
        files={"file": ("evidence.bin", b"abc123", "application/octet-stream")},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["case_id"] == case_id
    assert body["original_filename"] == "evidence.bin"
    assert body["mime_type"] == "application/octet-stream"
    assert body["file_size"] == 6
    assert body["status"] == "active"
    assert Path(body["storage_path"]).exists()


def test_unassigned_investigator_cannot_upload(client, user_factory, login_headers):
    owner = user_factory(role="investigator", username="owner_case")
    headers = login_headers(owner.username, "Passw0rd!x")
    created = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-UPLOAD-4"),
    )
    case_id = created.json()["id"]

    other = user_factory(role="investigator", username="other_case")
    other_headers = login_headers(other.username, "Passw0rd!x")
    resp = client.post(
        "/api/evidence/upload",
        headers=other_headers,
        data={"case_id": case_id, "description": "Should fail"},
        files={"file": ("other.bin", b"data", "application/octet-stream")},
    )
    assert resp.status_code == 403


def test_upload_rejects_path_traversal_filename(client, user_factory, login_headers):
    investigator = user_factory(role="investigator", username="inv_traversal")
    headers = login_headers(investigator.username, "Passw0rd!x")
    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-UPLOAD-5"),
    )
    case_id = case.json()["id"]

    resp = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id},
        files={"file": ("../../evil.bin", b"bad", "application/octet-stream")},
    )
    assert resp.status_code == 400


def test_duplicate_upload_name_does_not_overwrite(client, user_factory, login_headers):
    investigator = user_factory(role="investigator", username="inv_duplicate")
    headers = login_headers(investigator.username, "Passw0rd!x")
    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-UPLOAD-DUP"),
    )
    case_id = case.json()["id"]

    first = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "first"},
        files={"file": ("dup.bin", b"one", "application/octet-stream")},
    )
    assert first.status_code == 201

    second = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "second"},
        files={"file": ("dup.bin", b"two", "application/octet-stream")},
    )
    assert second.status_code == 201
    assert first.json()["id"] != second.json()["id"]
