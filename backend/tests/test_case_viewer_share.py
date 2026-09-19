"""Investigator -> Viewer case sharing (``case_viewers``) tests.

Covers:
- share/revoke lifecycle (investigator owner, admin, assigned investigator)
- viewer read-only access: case list/detail, evidence list/detail,
  custody history, report list + download (shared cases only)
- hard denials: edit/assign case, upload/verify evidence, append custody,
  share/unshare, generate reports, admin endpoints
- IDOR/BOLA: viewer cannot reach unshared case/evidence/reports by id
- business rules: created_by_id / assigned_investigator_id unchanged,
  audit events, idempotent re-share, target validation
"""

from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.audit_log import AuditLog
from app.models.case import case_viewers
from app.models.custody_transfer import CustodyTransfer
from app.models.evidence import Evidence
from app.models.evidence_hash import EvidenceHash

CASE_PAYLOAD = {
    "case_number": "CASE-SHARE-1",
    "title": "Viewer sharing case",
    "description": "Shared viewer read-only test",
    "offense": "Burglary",
    "victim": "ACME Corp",
    "suspect": "Unknown",
    "submitting_officer": "Det. Owner",
    "location": "1 Main St",
    "status": "open",
}

PASSWORD = "Passw0rd!x"


@pytest.fixture(autouse=True)
def _isolated_reports_dir(monkeypatch, tmp_path):
    """Redirect report PDF output to a temp dir (matches test_reports.py)."""
    monkeypatch.setattr("app.api.routers.reports._reports_dir", lambda: tmp_path)


def hdr(login_headers, user):
    return login_headers(user.username, PASSWORD)


def _make_case(client, headers, number):
    resp = client.post(
        "/api/cases", headers=headers, json=dict(CASE_PAYLOAD, case_number=number)
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_evidence(db_session, case, owner, number="disk-share-01.E01") -> Evidence:
    # Accept either the ORM Case or the API-created case dict.
    case_id = case["id"] if isinstance(case, dict) else case.id
    evidence = Evidence(
        case_id=case_id,
        item_number=1,
        original_filename=number,
        storage_path="cases/test/share-evidence.bin",
        mime_type="application/octet-stream",
        file_size=1024,
        description="shared evidence",
        status="active",
        uploaded_by_id=owner.id,
    )
    db_session.add(evidence)
    db_session.flush()
    db_session.add(
        EvidenceHash(
            evidence_id=evidence.id,
            sha256_hex="b" * 64,
            algorithm="sha256",
            hash_type="original",
        )
    )
    db_session.add(
        CustodyTransfer(
            evidence_id=evidence.id,
            previous_custodian_id=None,
            new_custodian_id=owner.id,
            authorized_by_id=owner.id,
            action="created",
            reason="Evidence created",
        )
    )
    db_session.flush()
    return evidence


def _share(client, headers, case_id, viewer_id):
    return client.post(
        f"/api/cases/{case_id}/viewers",
        headers=headers,
        json={"viewer_id": str(viewer_id)},
    )


class TestShareLifecycle:
    def test_owner_share_admin_share_assigned_share(
        self, client, db_session, user_factory, login_headers
    ):
        owner = user_factory(role="investigator", username="shr_owner")
        admin_user = user_factory(role="admin", username="shr_admin")
        assignee = user_factory(role="investigator", username="shr_assignee")
        viewer = user_factory(role="viewer", username="shr_view")
        v2 = user_factory(role="viewer", username="shr_view2")
        owner_h, admin_h, assignee_h = (
            hdr(login_headers, owner),
            hdr(login_headers, admin_user),
            hdr(login_headers, assignee),
        )
        case = _make_case(client, owner_h, "CASE-SHARE-A")

        # Owner shares.
        resp = _share(client, owner_h, case["id"], viewer.id)
        assert resp.status_code == 201, resp.text
        assert resp.json()["username"] == viewer.username

        # Admin shares a second viewer.
        assert _share(client, admin_h, case["id"], v2.id).status_code == 201

        # Assigned investigator (not owner) can also share.
        patch = client.patch(
            f"/api/cases/{case['id']}",
            headers=admin_h,
            json={"assigned_investigator_id": str(assignee.id)},
        )
        assert patch.status_code == 200, patch.text
        another = user_factory(role="viewer", username="shr_view3")
        assert _share(client, assignee_h, case["id"], another.id).status_code == 201

        listed = client.get(f"/api/cases/{case['id']}/viewers", headers=owner_h)
        assert listed.status_code == 200
        names = {v["username"] for v in listed.json()}
        assert names == {viewer.username, v2.username, another.username}

    def test_sharing_does_not_change_owner_or_assignment(
        self, client, db_session, user_factory, login_headers
    ):
        owner = user_factory(role="investigator", username="shr_own2")
        viewer = user_factory(role="viewer", username="shr_view4")
        owner_h = hdr(login_headers, owner)
        case = _make_case(client, owner_h, "CASE-SHARE-B")

        assert _share(client, owner_h, case["id"], viewer.id).status_code == 201
        got = client.get(f"/api/cases/{case['id']}", headers=owner_h).json()
        assert got["created_by_id"] == case["created_by_id"] == str(owner.id)
        assert got["assigned_investigator_id"] == case["assigned_investigator_id"]

    def test_share_creates_audit_event(self, client, db_session, user_factory, login_headers):
        owner = user_factory(role="investigator", username="shr_own3")
        viewer = user_factory(role="viewer", username="shr_view5")
        owner_h = hdr(login_headers, owner)
        case = _make_case(client, owner_h, "CASE-SHARE-C")

        assert _share(client, owner_h, case["id"], viewer.id).status_code == 201
        events = db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "CASE_SHARED_WITH_VIEWER",
                AuditLog.resource_id == case["id"],
            )
        ).scalars().all()
        assert len(events) == 1
        assert events[0].details["viewer_id"] == str(viewer.id)

    def test_duplicate_share_is_idempotent(
        self, client, db_session, user_factory, login_headers
    ):
        owner = user_factory(role="investigator", username="shr_own4")
        viewer = user_factory(role="viewer", username="shr_view6")
        owner_h = hdr(login_headers, owner)
        case = _make_case(client, owner_h, "CASE-SHARE-D")

        assert _share(client, owner_h, case["id"], viewer.id).status_code == 201
        again = _share(client, owner_h, case["id"], viewer.id)
        assert again.status_code == 200
        rows = db_session.execute(
            select(case_viewers).where(case_viewers.c.case_id == case["id"])
        ).all()
        assert len(rows) == 1
        events = db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "CASE_SHARED_WITH_VIEWER",
                AuditLog.resource_id == case["id"],
            )
        ).scalars().all()
        assert len(events) == 1  # no duplicate audit event

    def test_revoke_removes_access_and_audits(
        self, client, db_session, user_factory, login_headers
    ):
        owner = user_factory(role="investigator", username="shr_own5")
        viewer = user_factory(role="viewer", username="shr_view7")
        owner_h, viewer_h = hdr(login_headers, owner), hdr(login_headers, viewer)
        case = _make_case(client, owner_h, "CASE-SHARE-E")

        assert _share(client, owner_h, case["id"], viewer.id).status_code == 201
        assert client.get(f"/api/cases/{case['id']}", headers=viewer_h).status_code == 200

        resp = client.delete(
            f"/api/cases/{case['id']}/viewers/{viewer.id}", headers=owner_h
        )
        assert resp.status_code == 204
        assert client.get(f"/api/cases/{case['id']}", headers=viewer_h).status_code == 403
        assert client.get(f"/api/cases/{case['id']}/viewers", headers=owner_h).json() == []

        events = db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "CASE_UNSHARED_FROM_VIEWER",
                AuditLog.resource_id == case["id"],
            )
        ).scalars().all()
        assert len(events) == 1

        # Revoking again: 404 (not shared).
        assert (
            client.delete(
                f"/api/cases/{case['id']}/viewers/{viewer.id}", headers=owner_h
            ).status_code
            == 404
        )

    def test_share_validations(self, client, db_session, user_factory, login_headers):
        owner = user_factory(role="investigator", username="shr_own6")
        viewer = user_factory(role="viewer", username="shr_view8")
        inactive = user_factory(role="viewer", username="shr_view9_inactive")
        inactive.is_active = False
        other_inv = user_factory(role="investigator", username="shr_inv9")
        db_session.flush()
        owner_h = hdr(login_headers, owner)
        case = _make_case(client, owner_h, "CASE-SHARE-F")

        assert _share(client, owner_h, case["id"], uuid4()).status_code == 422
        assert _share(client, owner_h, case["id"], other_inv.id).status_code == 422
        assert _share(client, owner_h, case["id"], inactive.id).status_code == 422
        assert _share(client, owner_h, uuid4(), viewer.id).status_code == 404

        # Mass-assignment guard: extra fields are rejected.
        resp = client.post(
            f"/api/cases/{case['id']}/viewers",
            headers=owner_h,
            json={"viewer_id": str(viewer.id), "assigned_investigator_id": str(owner.id)},
        )
        assert resp.status_code == 422

    def test_unassigned_investigator_cannot_share(
        self, client, db_session, user_factory, login_headers
    ):
        owner = user_factory(role="investigator", username="shr_own7")
        other = user_factory(role="investigator", username="shr_inv8")
        viewer = user_factory(role="viewer", username="shr_view10")
        case = _make_case(client, hdr(login_headers, owner), "CASE-SHARE-G")
        resp = _share(client, hdr(login_headers, other), case["id"], viewer.id)
        assert resp.status_code == 403

    def test_viewer_options_lists_only_active_viewers(
        self, client, db_session, user_factory, login_headers
    ):
        inv = user_factory(role="investigator", username="shr_opt_inv")
        admin_user = user_factory(role="admin", username="shr_opt_admin")
        viewer = user_factory(role="viewer", username="shr_opt_view")
        gone = user_factory(role="viewer", username="shr_opt_gone")
        gone.is_active = False
        db_session.flush()

        resp = client.get("/api/viewers", headers=hdr(login_headers, inv))
        assert resp.status_code == 200
        data = resp.json()
        usernames = {u["username"] for u in data}
        assert viewer.username in usernames
        assert gone.username not in usernames
        assert inv.username not in usernames and admin_user.username not in usernames
        for entry in data:  # safe fields only
            assert set(entry.keys()) == {"id", "username"}

        # Viewers themselves cannot enumerate shareable viewers.
        assert (
            client.get("/api/viewers", headers=hdr(login_headers, viewer)).status_code
            == 403
        )


class TestSharedViewerRead:
    def _setup(self, client, db_session, user_factory, login_headers, number):
        owner = user_factory(role="investigator", username=f"shr_read_{number}")
        viewer = user_factory(role="viewer", username=f"shr_rview_{number}")
        owner_h, viewer_h = hdr(login_headers, owner), hdr(login_headers, viewer)
        case = _make_case(client, owner_h, f"CASE-SHARE-R{number}")
        evidence = _make_evidence(db_session, case, owner)
        report = client.post(f"/api/reports/case/{case['id']}", headers=owner_h).json()
        assert report.get("id"), report
        assert _share(client, owner_h, case["id"], viewer.id).status_code == 201
        return owner, viewer, owner_h, viewer_h, case, evidence, report

    def test_viewer_reads_shared_case_list_and_detail(
        self, client, db_session, user_factory, login_headers
    ):
        _, _, _, viewer_h, case, _, _ = self._setup(
            client, db_session, user_factory, login_headers, 1
        )
        listed = client.get("/api/cases", headers=viewer_h)
        assert listed.status_code == 200
        assert case["id"] in [c["id"] for c in listed.json()]
        got = client.get(f"/api/cases/{case['id']}", headers=viewer_h)
        assert got.status_code == 200
        assert got.json()["case_number"] == case["case_number"]

    def test_viewer_cannot_access_unshared_case(
        self, client, db_session, user_factory, login_headers
    ):
        _, _, owner_h, viewer_h, _, _, _ = self._setup(
            client, db_session, user_factory, login_headers, 2
        )
        other = _make_case(client, owner_h, "CASE-SHARE-R2-UNSHARED")
        # Not shared, not created/assigned to viewer -> 403, absent from list.
        assert client.get(f"/api/cases/{other['id']}", headers=viewer_h).status_code == 403
        ids = [c["id"] for c in client.get("/api/cases", headers=viewer_h).json()]
        assert other["id"] not in ids

    def test_viewer_reads_shared_evidence_list_and_detail(
        self, client, db_session, user_factory, login_headers
    ):
        _, _, _, viewer_h, case, evidence, _ = self._setup(
            client, db_session, user_factory, login_headers, 3
        )
        listed = client.get(f"/api/evidence?case_id={case['id']}", headers=viewer_h)
        assert listed.status_code == 200
        assert str(evidence.id) in [e["id"] for e in listed.json()]
        assert client.get(f"/api/evidence/{evidence.id}", headers=viewer_h).status_code == 200

    def test_viewer_denied_unshared_evidence(
        self, client, db_session, user_factory, login_headers
    ):
        owner, _, owner_h, viewer_h, _, _, _ = self._setup(
            client, db_session, user_factory, login_headers, 5
        )
        other = _make_case(client, owner_h, "CASE-SHARE-R5-UNSHARED")
        other_evidence = _make_evidence(db_session, other, owner, "hidden.E01")
        assert (
            client.get(f"/api/evidence?case_id={other['id']}", headers=viewer_h).status_code
            == 403
        )
        assert (
            client.get(f"/api/evidence/{other_evidence.id}", headers=viewer_h).status_code
            == 403
        )

    def test_viewer_reads_shared_custody_history(
        self, client, db_session, user_factory, login_headers
    ):
        owner, _, _, viewer_h, _, evidence, _ = self._setup(
            client, db_session, user_factory, login_headers, 6
        )
        resp = client.get(f"/api/evidence/{evidence.id}/custody", headers=viewer_h)
        assert resp.status_code == 200
        history = resp.json()
        assert len(history) == 1
        assert history[0]["received_by"] == owner.username

    def test_viewer_reads_and_downloads_shared_reports(
        self, client, db_session, user_factory, login_headers
    ):
        _, _, _, viewer_h, case, _, report = self._setup(
            client, db_session, user_factory, login_headers, 7
        )
        listed = client.get(f"/api/reports/case/{case['id']}", headers=viewer_h)
        assert listed.status_code == 200
        assert report["id"] in [r["id"] for r in listed.json()]
        download = client.get(f"/api/reports/{report['id']}/download", headers=viewer_h)
        assert download.status_code == 200
        assert download.content.startswith(b"%PDF-")

    def test_viewer_denied_other_case_reports(
        self, client, db_session, user_factory, login_headers
    ):
        _, _, owner_h, viewer_h, _, _, _ = self._setup(
            client, db_session, user_factory, login_headers, 8
        )
        other = _make_case(client, owner_h, "CASE-SHARE-R8-UNSHARED")
        other_report = client.post(f"/api/reports/case/{other['id']}", headers=owner_h).json()
        assert client.get(f"/api/reports/case/{other['id']}", headers=viewer_h).status_code == 403
        assert (
            client.get(f"/api/reports/{other_report['id']}/download", headers=viewer_h).status_code
            == 403
        )


class TestViewerDenials:
    def _setup(self, client, db_session, user_factory, login_headers):
        owner = user_factory(role="investigator", username="shr_d_owner")
        viewer = user_factory(role="viewer", username="shr_d_view")
        owner_h, viewer_h = hdr(login_headers, owner), hdr(login_headers, viewer)
        case = _make_case(client, owner_h, "CASE-SHARE-DENY")
        evidence = _make_evidence(db_session, case, owner)
        assert _share(client, owner_h, case["id"], viewer.id).status_code == 201
        return owner, viewer, owner_h, viewer_h, case, evidence

    def test_viewer_cannot_edit_or_assign_case(
        self, client, db_session, user_factory, login_headers
    ):
        _, viewer, _, viewer_h, case, _ = self._setup(
            client, db_session, user_factory, login_headers
        )
        assert (
            client.patch(
                f"/api/cases/{case['id']}",
                headers=viewer_h,
                json={"status": "closed"},
            ).status_code
            == 403
        )
        # Assignment-change attempt (privilege escalation) also denied.
        assert (
            client.patch(
                f"/api/cases/{case['id']}",
                headers=viewer_h,
                json={"assigned_investigator_id": str(viewer.id)},
            ).status_code
            == 403
        )

    def test_viewer_cannot_delete_case(
        self, client, db_session, user_factory, login_headers
    ):
        _, _, _, viewer_h, case, _ = self._setup(
            client, db_session, user_factory, login_headers
        )
        # No DELETE route exists: FastAPI answers 405 (denied) - never 2xx.
        resp = client.delete(f"/api/cases/{case['id']}", headers=viewer_h)
        assert resp.status_code in (403, 405)

    def test_viewer_cannot_upload_or_verify_evidence(
        self, client, db_session, user_factory, login_headers
    ):
        _, viewer, _, viewer_h, case, evidence = self._setup(
            client, db_session, user_factory, login_headers
        )
        upload = client.post(
            "/api/evidence/upload",
            headers=viewer_h,
            data={"case_id": case["id"], "description": "x"},
            files={"file": ("t.bin", b"data", "application/octet-stream")},
        )
        assert upload.status_code == 403
        assert (
            client.post(f"/api/evidence/verify/{evidence.id}", headers=viewer_h).status_code
            == 403
        )

    def test_viewer_cannot_append_custody(
        self, client, db_session, user_factory, login_headers
    ):
        owner, viewer, _, viewer_h, _, evidence = self._setup(
            client, db_session, user_factory, login_headers
        )
        resp = client.post(
            f"/api/evidence/{evidence.id}/custody",
            headers=viewer_h,
            json={
                "received_by_id": str(owner.id),
                "action": "transferred",
                "comments": "viewer attempt",
                "location": "lab",
            },
        )
        assert resp.status_code == 403

    def test_viewer_cannot_share_revoke_generate_or_admin(
        self, client, db_session, user_factory, login_headers
    ):
        owner, viewer, _, viewer_h, case, _ = self._setup(
            client, db_session, user_factory, login_headers
        )
        other_viewer = user_factory(role="viewer", username="shr_d_view2")
        # Manage gate: viewers can neither share nor revoke.
        assert _share(client, viewer_h, case["id"], other_viewer.id).status_code == 403
        assert (
            client.delete(
                f"/api/cases/{case['id']}/viewers/{owner.id}", headers=viewer_h
            ).status_code
            == 403
        )
        # Viewer cannot enumerate the case's share list (share management).
        assert (
            client.get(f"/api/cases/{case['id']}/viewers", headers=viewer_h).status_code
            == 403
        )
        # Viewer cannot generate reports.
        assert client.post(f"/api/reports/case/{case['id']}", headers=viewer_h).status_code == 403
        # Viewer cannot access admin endpoints.
        assert client.get("/api/admin/users", headers=viewer_h).status_code == 403

    def test_unauthenticated_share_401(self, client):
        resp = client.post(
            f"/api/cases/{uuid4()}/viewers", json={"viewer_id": str(uuid4())}
        )
        assert resp.status_code == 401
