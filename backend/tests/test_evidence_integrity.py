"""Integrity verification tests for Stage 11."""

import hashlib
from pathlib import Path

from sqlalchemy import text

from app.models.evidence_hash import EvidenceHash
from app.security.encryption import encrypt_evidence


CASE_PAYLOAD = {
    "case_number": "CASE-INTEGRITY-1",
    "title": "Evidence integrity test",
    "description": "Verify SHA-256 hashing",
    "offense": "Theft",
    "victim": "ACME",
    "suspect": "Unknown",
    "submitting_officer": "Det. Jones",
    "location": "Warehouse",
    "status": "open",
}


def test_upload_creates_original_hash(client, user_factory, login_headers, db_session):
    """Evidence upload should compute and store original SHA-256 hash."""
    investigator = user_factory(role="investigator", username="inv_hash1")
    headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-HASH1"),
    )
    case_id = case.json()["id"]

    content = b"test evidence data for hash"
    resp = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Hash test"},
        files={"file": ("test.bin", content, "application/octet-stream")},
    )
    assert resp.status_code == 201
    evidence_id = resp.json()["id"]

    evidence_hashes = db_session.query(EvidenceHash).filter(
        EvidenceHash.evidence_id == evidence_id,
        EvidenceHash.hash_type == "original",
    ).all()
    
    assert len(evidence_hashes) > 0
    expected_hash = hashlib.sha256(content).hexdigest()
    assert evidence_hashes[0].sha256_hex == expected_hash


def test_verify_matching_hash(client, user_factory, login_headers):
    """Verification should pass when file unchanged."""
    investigator = user_factory(role="investigator", username="inv_verify1")
    headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-VERIFY1"),
    )
    case_id = case.json()["id"]

    content = b"unchanged evidence data"
    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Verify test"},
        files={"file": ("verify.bin", content, "application/octet-stream")},
    )
    evidence_id = upload.json()["id"]

    resp = client.post(
        f"/api/evidence/verify/{evidence_id}",
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["match"] is True
    assert body["status"] == "INTEGRITY VERIFIED"
    assert body["evidence_id"] == evidence_id
    assert body["filename"] == "verify.bin"
    assert body["algorithm"] == "SHA256"
    assert body["verified_by"] == investigator.username


def test_verify_mismatched_hash_on_tampering(client, user_factory, login_headers):
    """Verification should fail if file content changed."""
    investigator = user_factory(role="investigator", username="inv_tamp1")
    headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-TAMP1"),
    )
    case_id = case.json()["id"]

    original_content = b"original evidence"
    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Tampering test"},
        files={"file": ("tamp.bin", original_content, "application/octet-stream")},
    )
    evidence = upload.json()
    evidence_id = evidence["id"]
    storage_path = evidence["storage_path"]

    Path(storage_path).write_bytes(encrypt_evidence(b"tampered evidence"))

    resp = client.post(
        f"/api/evidence/verify/{evidence_id}",
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["match"] is False
    assert body["status"] == "INTEGRITY VIOLATION"
    assert body["filename"] == "tamp.bin"
    assert body["algorithm"] == "SHA256"
    assert body["verified_by"] == investigator.username


def test_verify_large_file_hash(client, user_factory, login_headers):
    """Verification should handle large files correctly."""
    investigator = user_factory(role="investigator", username="inv_large1")
    headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-LARGE1"),
    )
    case_id = case.json()["id"]

    large_content = b"x" * (10 * 1024 * 1024)
    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Large file test"},
        files={"file": ("large.bin", large_content, "application/octet-stream")},
    )
    evidence_id = upload.json()["id"]

    resp = client.post(
        f"/api/evidence/verify/{evidence_id}",
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["match"] is True


def test_verify_repeated_verification(client, user_factory, login_headers):
    """Multiple verification attempts should produce consistent results."""
    investigator = user_factory(role="investigator", username="inv_repeat1")
    headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-REPEAT1"),
    )
    case_id = case.json()["id"]

    content = b"stable evidence"
    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Repeated verification test"},
        files={"file": ("repeat.bin", content, "application/octet-stream")},
    )
    evidence_id = upload.json()["id"]

    for _ in range(3):
        resp = client.post(
            f"/api/evidence/verify/{evidence_id}",
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["match"] is True
        assert resp.json()["status"] == "INTEGRITY VERIFIED"


def test_verify_missing_evidence_file(client, user_factory, login_headers):
    """Verification should fail if file missing on disk."""
    investigator = user_factory(role="investigator", username="inv_missing1")
    headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-MISSING1"),
    )
    case_id = case.json()["id"]

    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Missing file test"},
        files={"file": ("missing.bin", b"content", "application/octet-stream")},
    )
    evidence = upload.json()
    evidence_id = evidence["id"]
    storage_path = evidence["storage_path"]

    Path(storage_path).unlink()

    resp = client.post(
        f"/api/evidence/verify/{evidence_id}",
        headers=headers,
    )
    assert resp.status_code == 410


def test_verify_unauthorized_case_access(client, user_factory, login_headers):
    """Verification should be blocked if user cannot access case."""
    owner = user_factory(role="investigator", username="inv_owner1")
    owner_headers = login_headers(owner.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=owner_headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-UNAUTH1"),
    )
    case_id = case.json()["id"]

    upload = client.post(
        "/api/evidence/upload",
        headers=owner_headers,
        data={"case_id": case_id, "description": "Unauthorized access test"},
        files={"file": ("unauth.bin", b"data", "application/octet-stream")},
    )
    evidence_id = upload.json()["id"]

    other = user_factory(role="investigator", username="inv_other1")
    other_headers = login_headers(other.username, "Passw0rd!x")

    resp = client.post(
        f"/api/evidence/verify/{evidence_id}",
        headers=other_headers,
    )
    assert resp.status_code == 403


def test_verify_viewer_cannot_verify(client, user_factory, login_headers):
    """Viewers should not be able to verify evidence."""
    viewer = user_factory(role="viewer", username="viewer_verify1")
    investigator = user_factory(role="investigator", username="inv_viewer1")

    inv_headers = login_headers(investigator.username, "Passw0rd!x")
    case = client.post(
        "/api/cases",
        headers=inv_headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-VIEWER1"),
    )
    case_id = case.json()["id"]

    upload = client.post(
        "/api/evidence/upload",
        headers=inv_headers,
        data={"case_id": case_id, "description": "Viewer access test"},
        files={"file": ("viewer.bin", b"data", "application/octet-stream")},
    )
    evidence_id = upload.json()["id"]

    viewer_headers = login_headers(viewer.username, "Passw0rd!x")
    resp = client.post(
        f"/api/evidence/verify/{evidence_id}",
        headers=viewer_headers,
    )
    assert resp.status_code == 403


def test_verify_invalid_evidence_id(client, user_factory, login_headers):
    """Verification with invalid evidence_id should return 422."""
    investigator = user_factory(role="investigator", username="inv_invalid1")
    headers = login_headers(investigator.username, "Passw0rd!x")

    resp = client.post(
        "/api/evidence/verify/invalid-uuid",
        headers=headers,
    )
    assert resp.status_code == 422


def test_verify_nonexistent_evidence(client, user_factory, login_headers):
    """Verification of nonexistent evidence should return 404."""
    investigator = user_factory(role="investigator", username="inv_notfound1")
    headers = login_headers(investigator.username, "Passw0rd!x")

    import uuid
    fake_id = str(uuid.uuid4())
    resp = client.post(
        f"/api/evidence/verify/{fake_id}",
        headers=headers,
    )
    assert resp.status_code == 404


def test_original_hash_never_replaced_after_mismatch(client, user_factory, login_headers, db_session):
    """Original hash should persist even after tampering and verification."""
    investigator = user_factory(role="investigator", username="inv_persist1")
    headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-PERSIST1"),
    )
    case_id = case.json()["id"]

    original_content = b"immutable evidence"
    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Hash persistence test"},
        files={"file": ("persist.bin", original_content, "application/octet-stream")},
    )
    evidence_id = upload.json()["id"]
    storage_path = upload.json()["storage_path"]

    original_hash = hashlib.sha256(original_content).hexdigest()

    Path(storage_path).write_bytes(encrypt_evidence(b"tampered content"))
    client.post(f"/api/evidence/verify/{evidence_id}", headers=headers)

    hashes = db_session.query(EvidenceHash).filter(
        EvidenceHash.evidence_id == evidence_id
    ).all()

    original_record = [h for h in hashes if h.hash_type == "original"]
    assert len(original_record) == 1
    assert original_record[0].sha256_hex == original_hash

    verification_record = [h for h in hashes if h.hash_type == "verification"]
    assert len(verification_record) == 1
    assert verification_record[0].sha256_hex != original_hash


def test_admin_can_verify_any_evidence(client, user_factory, login_headers):
    """Admins should be able to verify evidence in any case."""
    investigator = user_factory(role="investigator", username="inv_admin_verify1")
    inv_headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=inv_headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-ADMIN1"),
    )
    case_id = case.json()["id"]

    upload = client.post(
        "/api/evidence/upload",
        headers=inv_headers,
        data={"case_id": case_id, "description": "Admin verify test"},
        files={"file": ("admin.bin", b"data", "application/octet-stream")},
    )
    evidence_id = upload.json()["id"]

    admin = user_factory(role="admin", username="admin_verify")
    admin_headers = login_headers(admin.username, "Passw0rd!x")

    resp = client.post(
        f"/api/evidence/verify/{evidence_id}",
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["match"] is True


def test_verify_audit_log_on_success(client, user_factory, login_headers, db_session):
    """Successful verification should create audit log with match details."""
    from app.models.audit_log import AuditLog
    
    investigator = user_factory(role="investigator", username="inv_audit_ok")
    headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-AUDIT-OK"),
    )
    case_id = case.json()["id"]

    content = b"audit test content"
    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Audit test"},
        files={"file": ("audit.bin", content, "application/octet-stream")},
    )
    evidence_id = upload.json()["id"]

    client.post(f"/api/evidence/verify/{evidence_id}", headers=headers)

    audits = db_session.query(AuditLog).filter(
        AuditLog.action == "INTEGRITY_CHECK",
        AuditLog.resource_id == str(evidence_id),
    ).all()
    assert len(audits) > 0
    assert audits[0].result == "success"
    assert audits[0].details["status"] == "INTEGRITY VERIFIED"


def test_verify_audit_log_on_mismatch(client, user_factory, login_headers, db_session):
    """Failed verification should create audit log with violation details."""
    from app.models.audit_log import AuditLog
    
    investigator = user_factory(role="investigator", username="inv_audit_fail")
    headers = login_headers(investigator.username, "Passw0rd!x")

    case = client.post(
        "/api/cases",
        headers=headers,
        json=dict(CASE_PAYLOAD, case_number="CASE-INTEGRITY-AUDIT-FAIL"),
    )
    case_id = case.json()["id"]

    upload = client.post(
        "/api/evidence/upload",
        headers=headers,
        data={"case_id": case_id, "description": "Tampering audit test"},
        files={"file": ("tamper_audit.bin", b"original", "application/octet-stream")},
    )
    evidence = upload.json()
    evidence_id = evidence["id"]
    storage_path = evidence["storage_path"]

    Path(storage_path).write_bytes(encrypt_evidence(b"modified"))
    client.post(f"/api/evidence/verify/{evidence_id}", headers=headers)

    audits = db_session.query(AuditLog).filter(
        AuditLog.action == "INTEGRITY_CHECK",
        AuditLog.resource_id == str(evidence_id),
    ).all()
    assert len(audits) > 0
    assert audits[0].result == "failure"
    assert audits[0].details["status"] == "INTEGRITY VIOLATION"
    assert audits[0].details["match"] is False
