"""Stage 19 tests - PDF chain-of-custody report generation.

Covers:
- reference-form structure (headings/sections) in the report story
- generation creates a ReportRecord + REPORT_GENERATED ledger event
- unique report identifiers across generations
- PDF bytes (magic header) and download endpoint (content type, auth, 404)
- authorization (401 unauthenticated, 403 viewer / unassigned investigator)
- missing optional fields render as "Not Provided"
- multiple evidence items and multiple custody transfers (long comments)

Report PDFs are written to a temporary directory (monkeypatched via
``_reports_dir``) so tests never pollute the real ``reports/`` folder.
"""

from datetime import datetime, timedelta, timezone

import uuid

import pytest

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.evidence_hash import EvidenceHash
from app.models.custody_transfer import CustodyTransfer
from app.models.report_record import ReportRecord
from app.reports import generator as report_generator


@pytest.fixture(autouse=True)
def _isolated_reports_dir(monkeypatch, tmp_path):
    """Redirect report PDF output to a temp dir for every test."""
    monkeypatch.setattr("app.api.routers.reports._reports_dir", lambda: tmp_path)
    return tmp_path


CASE_PAYLOAD = {
    "case_number": "CASE-REPORT-1",
    "title": "Chain-of-custody reporting",
    "description": "Report generation test case",
    "offense": "Unauthorized Access",
    "victim": "ACME Corp",
    "suspect": "Unknown",
    "submitting_officer": "Det. Jane Doe / Badge 4411",
    "location": "Server Room B, 2nd Floor",
    "seized_at": "2026-08-01T09:30:00Z",
    "status": "open",
}


def _make_case(db_session, user, **overrides) -> Case:
    payload = dict(CASE_PAYLOAD)
    payload.update(overrides)
    case = Case(
        case_number=payload["case_number"],
        title=payload["title"],
        description=payload["description"],
        offense=payload["offense"],
        victim=payload["victim"],
        suspect=payload["suspect"],
        submitting_officer=payload["submitting_officer"],
        location=payload["location"],
        seized_at=payload["seized_at"] if isinstance(payload["seized_at"], datetime) else datetime(2026, 8, 1, 9, 30, tzinfo=timezone.utc),
        status="open",
        created_by_id=user.id,
        assigned_investigator_id=user.id,
    )
    db_session.add(case)
    db_session.flush()
    return case


def _make_evidence(db_session, case, uploader, item_number=None, description=None) -> Evidence:
    evidence = Evidence(
        case_id=case.id,
        item_number=item_number,
        original_filename="disk-image-01.E01",
        storage_path="cases/test/disk-image-01-uuid.bin",
        mime_type="application/octet-stream",
        file_size=1024,
        description=description,
        status="active",
        uploaded_by_id=uploader.id,
    )
    db_session.add(evidence)
    db_session.flush()
    db_session.add(
        EvidenceHash(
            evidence_id=evidence.id,
            sha256_hex="a" * 64,
            algorithm="sha256",
            hash_type="original",
        )
    )
    db_session.flush()
    return evidence


def _story_text(story) -> str:
    chunks = []

    def _walk(flowables):
        for flowable in flowables:
            text = getattr(flowable, "text", None)
            if text:
                chunks.append(text)
            inner = getattr(flowable, "_content", None)  # KeepTogether
            if inner:
                _walk(inner)
                continue
            cells = getattr(flowable, "_cellvalues", None)  # Table
            if cells:
                for row in cells:
                    for cell in row:
                        cell_text = getattr(cell, "text", None)
                        if cell_text:
                            chunks.append(cell_text)
                        elif isinstance(cell, str):
                            chunks.append(cell)

    _walk(story)
    return "\n".join(chunks)


class TestReferenceFormStructure:
    def test_story_contains_all_reference_sections(self, db_session, user_factory):
        user = user_factory(role="investigator")
        case = _make_case(db_session, user)
        data = report_generator.collect_case_report_data(db_session, case, "COC-TEST-1")

        text = _story_text(report_generator.build_report_story(data))

        assert "EVIDENCE CHAIN OF CUSTODY TRACKING FORM" in text
        assert "Case Number:" in text
        assert "Offense:" in text
        assert "Submitting Officer (Name/ID#):" in text
        assert "Victim:" in text
        assert "Suspect:" in text
        assert "Date/Time Seized:" in text
        assert "Location of Seizure:" in text
        assert "DESCRIPTION OF EVIDENCE" in text
        assert "CHAIN OF CUSTODY" in text
        assert "FINAL DISPOSAL AUTHORITY" in text
        assert "FORENSIC ACKNOWLEDGMENT" in text

    def test_cmrs_information_integrated(self, db_session, user_factory):
        user = user_factory(role="investigator")
        case = _make_case(db_session, user)
        evidence = _make_evidence(db_session, case, user, item_number=1, description="Laptop drive")
        data = report_generator.collect_case_report_data(db_session, case, "COC-TEST-2")

        text = _story_text(report_generator.build_report_story(data))

        assert "CMRS DIGITAL EVIDENCE INFORMATION" in text
        assert "SHA-256" in text
        assert "Integrity Status" in text
        assert "Encryption Status" in text
        assert "AES-256-GCM ENCRYPTED (AT REST)" in text
        assert str(evidence.id) in text
        assert "a" * 32 in text  # SHA-256 rendered (wrapped over two lines)
        assert "Report ID: COC-TEST-2" in text

    def test_missing_optional_fields_render_not_provided(self, db_session, user_factory):
        user = user_factory(role="investigator")
        case = _make_case(
            db_session, user, case_number="CASE-REPORT-MIN", offense=None,
            victim=None, suspect=None, submitting_officer=None, location=None,
        )
        case.seized_at = None
        db_session.flush()
        data = report_generator.collect_case_report_data(db_session, case, "COC-TEST-3")

        text = _story_text(report_generator.build_report_story(data))

        assert "Not Provided" in text
        assert "No evidence items recorded for this case." in text
        assert "No custody events recorded for this case." in text

    def test_render_pdf_produces_pdf_bytes(self, db_session, user_factory):
        user = user_factory(role="investigator")
        case = _make_case(db_session, user)
        data = report_generator.collect_case_report_data(db_session, case, "COC-TEST-4")

        pdf_bytes = report_generator.render_pdf(data)

        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 1000


class TestDataCollection:
    def test_multiple_evidence_and_custody_transfers(self, db_session, user_factory):
        owner = user_factory(role="investigator", username="inv_report_owner")
        tech1 = user_factory(role="investigator", username="tech_one")
        tech2 = user_factory(role="investigator", username="tech_two")
        case = _make_case(db_session, owner)
        ev1 = _make_evidence(db_session, case, owner, item_number=1, description="Laptop")
        ev2 = _make_evidence(db_session, case, owner, item_number=2, description="Phone")

        base = datetime(2026, 8, 2, 10, 0, tzinfo=timezone.utc)
        long_comment = (
            "Transferred to forensic lab for imaging; drive sealed in evidence "
            "bag #E-9911, tamper-evident seal intact, transported in climate-"
            "controlled vehicle, chain unbroken at every hand-off step."
        )
        db_session.add_all(
            [
                CustodyTransfer(
                    evidence_id=ev1.id, previous_custodian_id=None,
                    new_custodian_id=owner.id, authorized_by_id=owner.id,
                    action="created", transferred_at=base,
                ),
                CustodyTransfer(
                    evidence_id=ev1.id, previous_custodian_id=owner.id,
                    new_custodian_id=tech1.id, authorized_by_id=owner.id,
                    action="transferred", reason=long_comment,
                    location="Forensic Lab A", transferred_at=base + timedelta(hours=1),
                ),
                CustodyTransfer(
                    evidence_id=ev1.id, previous_custodian_id=tech1.id,
                    new_custodian_id=tech2.id, authorized_by_id=tech1.id,
                    action="examined", transferred_at=base + timedelta(hours=2),
                ),
                CustodyTransfer(
                    evidence_id=ev2.id, previous_custodian_id=None,
                    new_custodian_id=owner.id, authorized_by_id=owner.id,
                    action="created", transferred_at=base + timedelta(minutes=5),
                ),
            ]
        )
        db_session.flush()

        data = report_generator.collect_case_report_data(db_session, case, "COC-TEST-5")

        assert len(data["items"]) == 2
        assert len(data["items"][0]["custody"]) == 3
        assert len(data["items"][1]["custody"]) == 1
        assert data["items"][0]["custody"][1]["comments"] == long_comment
        assert data["items"][0]["custody"][1]["released_by"] == "inv_report_owner"
        assert data["items"][0]["custody"][1]["received_by"] == "tech_one"
        assert data["items"][0]["integrity_status"] == "NOT VERIFIED"

        pdf_bytes = report_generator.render_pdf(data)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 1000

    def test_integrity_status_reflects_verification_hash(self, db_session, user_factory):
        user = user_factory(role="investigator")
        case = _make_case(db_session, user)
        evidence = _make_evidence(db_session, case, user)
        db_session.add(
            EvidenceHash(
                evidence_id=evidence.id, sha256_hex="b" * 64, algorithm="sha256",
                hash_type="verification", match_result=True,
                verified_at=datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
                verified_by_id=user.id,
            )
        )
        db_session.flush()

        data = report_generator.collect_case_report_data(db_session, case, "COC-TEST-6")
        assert data["items"][0]["integrity_status"] == "VERIFIED"

        db_session.add(
            EvidenceHash(
                evidence_id=evidence.id, sha256_hex="c" * 64, algorithm="sha256",
                hash_type="verification", match_result=False,
                verified_at=datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
                verified_by_id=user.id,
            )
        )
        db_session.flush()
        db_session.expire_all()  # refresh cached evidence.hashes collections
        data = report_generator.collect_case_report_data(db_session, case, "COC-TEST-6B")
        assert data["items"][0]["integrity_status"] == "MISMATCH"


class TestReportAPI:
    def test_generate_creates_record_and_audit_event(self, client, db_session, user_factory, login_headers):
        u = user_factory(role="investigator", username="inv_report_api")
        headers = login_headers(u.username, "Passw0rd!x")

        case_resp = client.post("/api/cases", json=CASE_PAYLOAD, headers=headers)
        assert case_resp.status_code == 201
        case_id = case_resp.json()["id"]

        resp = client.post(f"/api/reports/case/{case_id}", headers=headers)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["report_identifier"].startswith("COC-CASE-REPORT-1-")
        assert body["status"] == "generated"
        assert body["generated_by"] == "inv_report_api"
        assert body["download_url"] == f"/api/reports/{body['id']}/download"

        record = db_session.get(ReportRecord, uuid.UUID(body["id"]))
        assert record is not None

        from app.models.audit_log import AuditLog

        event = (
            db_session.query(AuditLog)
            .filter(AuditLog.action == "REPORT_GENERATED", AuditLog.resource_id == body["id"])
            .one_or_none()
        )
        assert event is not None

    def test_generate_unique_identifiers(self, client, user_factory, login_headers):
        u = user_factory(role="investigator", username="inv_report_uniq")
        headers = login_headers(u.username, "Passw0rd!x")
        case_resp = client.post("/api/cases", json=CASE_PAYLOAD, headers=headers)
        case_id = case_resp.json()["id"]

        ids = set()
        for _ in range(3):
            resp = client.post(f"/api/reports/case/{case_id}", headers=headers)
            assert resp.status_code == 201
            ids.add(resp.json()["report_identifier"])
        assert len(ids) == 3

    def test_download_returns_pdf(self, client, user_factory, login_headers):
        u = user_factory(role="investigator", username="inv_report_dl")
        headers = login_headers(u.username, "Passw0rd!x")
        case_resp = client.post("/api/cases", json=CASE_PAYLOAD, headers=headers)
        case_id = case_resp.json()["id"]
        gen = client.post(f"/api/reports/case/{case_id}", headers=headers).json()

        resp = client.get(f"/api/reports/{gen['id']}/download", headers=headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/pdf")
        assert resp.content.startswith(b"%PDF-")

    def test_download_missing_report_404(self, client, user_factory, login_headers):
        u = user_factory(role="investigator", username="inv_report_404")
        headers = login_headers(u.username, "Passw0rd!x")
        resp = client.get(f"/api/reports/{uuid.uuid4()}/download", headers=headers)
        assert resp.status_code == 404

    def test_list_reports_newest_first(self, client, user_factory, login_headers):
        u = user_factory(role="investigator", username="inv_report_list")
        headers = login_headers(u.username, "Passw0rd!x")
        case_resp = client.post("/api/cases", json=CASE_PAYLOAD, headers=headers)
        case_id = case_resp.json()["id"]
        for _ in range(2):
            client.post(f"/api/reports/case/{case_id}", headers=headers)

        resp = client.get(f"/api/reports/case/{case_id}", headers=headers)
        assert resp.status_code == 200
        listing = resp.json()
        assert len(listing) == 2
        assert listing[0]["generated_at"] >= listing[1]["generated_at"]

    def test_unauthenticated_401(self, client):
        assert client.post(f"/api/reports/case/{uuid.uuid4()}").status_code == 401
        assert client.get(f"/api/reports/{uuid.uuid4()}/download").status_code == 401

    def test_viewer_forbidden_403(self, client, db_session, user_factory, login_headers):
        owner = user_factory(role="investigator", username="inv_report_owner403")
        owner_headers = login_headers(owner.username, "Passw0rd!x")
        case_id = client.post("/api/cases", json=CASE_PAYLOAD, headers=owner_headers).json()["id"]

        v = user_factory(role="viewer", username="viewer_report")
        headers = login_headers(v.username, "Passw0rd!x")
        assert client.post(f"/api/reports/case/{case_id}", headers=headers).status_code == 403

    def test_unassigned_investigator_forbidden_403(self, client, db_session, user_factory, login_headers):
        owner = user_factory(role="investigator", username="inv_report_owner2")
        owner_headers = login_headers(owner.username, "Passw0rd!x")
        case_id = client.post("/api/cases", json=CASE_PAYLOAD, headers=owner_headers).json()["id"]

        other = user_factory(role="investigator", username="inv_report_other")
        headers = login_headers(other.username, "Passw0rd!x")
        assert client.post(f"/api/reports/case/{case_id}", headers=headers).status_code == 403
        assert client.get(f"/api/reports/case/{case_id}", headers=headers).status_code == 403



