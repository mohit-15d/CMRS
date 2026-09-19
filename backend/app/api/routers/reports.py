"""Chain-of-custody PDF report routes (Stage 19).

Endpoints:
- ``POST /api/reports/case/{case_id}``   generate the reference
  "EVIDENCE CHAIN OF CUSTODY TRACKING FORM" PDF for a case (investigator
  who can access the case, or admin). Values come exclusively from actual
  CMRS database records; optional fields render as "Not Provided".
- ``GET  /api/reports/case/{case_id}``   list generated reports for a case.
- ``GET  /api/reports/{report_id}/download``  stream the stored PDF.

Authorization is enforced server-side (RBAC + per-case IDOR checks). The
on-disk storage path is never exposed; downloads stream through this
router. Every generation appends a REPORT_GENERATED record to the chained
audit ledger.
"""

import re
import uuid

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import BACKEND_DIR, settings
from app.core.roles import ADMIN, INVESTIGATOR, VIEWER
from app.db.session import get_db
from app.models.case import Case, is_shared_with
from app.models.report_record import ReportRecord
from app.models.user import User
from app.reports.generator import collect_case_report_data, render_pdf
from app.schemas.reports import ReportRead
from app.security.audit_ledger import append_audit_event

router = APIRouter(prefix="/api/reports", tags=["reports"])

_IDENTIFIER_SAFE = re.compile(r"[^A-Za-z0-9-]+")


def _403() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def _get_accessible_case(db: Session, current_user: User, case_id: uuid.UUID) -> Case:
    """Resolve the case and enforce server-side WRITE access (IDOR-safe).

    Generation requires admin or an investigator who created/is assigned to the
    case. Viewers can never generate reports.
    """
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if current_user.role == ADMIN:
        return case
    if current_user.role != INVESTIGATOR:
        raise _403()
    if case.created_by_id != current_user.id and case.assigned_investigator_id != current_user.id:
        raise _403()
    return case


def _get_readable_case(db: Session, current_user: User, case_id: uuid.UUID) -> Case:
    """Resolve the case and enforce server-side READ access (IDOR-safe).

    Read access mirrors case visibility: admin, the creator, or the assigned
    reviewer (any role, including an assigned viewer). Used by report listing
    and download so an assigned viewer can retrieve generated PDFs read-only.
    """
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if current_user.role == ADMIN:
        return case
    if case.created_by_id != current_user.id and case.assigned_investigator_id != current_user.id:
        # Explicitly shared viewers may LIST/DOWNLOAD reports read-only for
        # their shared cases. Generation stays investigator/admin-only
        # (see _get_accessible_case).
        if current_user.role != VIEWER or not is_shared_with(db, case, current_user.id):
            raise _403()
    return case


def _reports_dir() -> Path:
    """Resolve (and create) the report storage directory from settings."""
    base = Path(settings.reports_storage_dir)
    if not base.is_absolute():
        base = (BACKEND_DIR / base).resolve()
    base.mkdir(parents=True, exist_ok=True)
    return base


def _new_report_identifier(case_number: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    safe_case = _IDENTIFIER_SAFE.sub("-", case_number).strip("-")[:40] or "CASE"
    return f"COC-{safe_case}-{stamp}-{uuid.uuid4().hex[:8]}"


def _to_read(db: Session, record: ReportRecord) -> ReportRead:
    generator = db.get(User, record.generated_by_id)
    return ReportRead(
        id=record.id,
        case_id=record.case_id,
        report_identifier=record.report_identifier,
        status=record.status,
        generated_at=record.generated_at,
        generated_by=generator.username if generator else None,
        download_url=f"/api/reports/{record.id}/download",
    )


@router.post("/case/{case_id}", response_model=ReportRead, status_code=status.HTTP_201_CREATED)
def generate_case_report(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ReportRead:
    """Generate the chain-of-custody PDF for a case from live DB records."""
    case = _get_accessible_case(db, current_user, case_id)

    report_identifier = _new_report_identifier(case.case_number)
    data = collect_case_report_data(db, case, report_identifier)
    pdf_bytes = render_pdf(data)

    destination = _reports_dir() / f"{report_identifier}.pdf"
    destination.write_bytes(pdf_bytes)

    record = ReportRecord(
        case_id=case.id,
        report_identifier=report_identifier,
        generated_by_id=current_user.id,
        storage_reference=str(destination),
        status="generated",
        generated_at=datetime.now(timezone.utc),
    )
    db.add(record)
    db.flush()
    append_audit_event(
        db,
        actor_id=current_user.id,
        action="REPORT_GENERATED",
        resource_type="report",
        resource_id=str(record.id),
        details={
            "report_identifier": report_identifier,
            "case_id": str(case.id),
            "evidence_count": len(data["items"]),
        },
    )
    db.commit()
    db.refresh(record)
    return _to_read(db, record)


@router.get("/case/{case_id}", response_model=list[ReportRead])
def list_case_reports(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ReportRead]:
    """List generated reports for an accessible case (newest first).

    Read access: admin, creator, or assigned reviewer (any role). Assigned
    viewers can list reports but cannot generate new ones.
    """
    case = _get_readable_case(db, current_user, case_id)
    records = (
        db.query(ReportRecord)
        .filter(ReportRecord.case_id == case.id)
        .order_by(ReportRecord.generated_at.desc())
        .all()
    )
    return [_to_read(db, r) for r in records]


@router.get("/{report_id}/download")
def download_report(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    """Stream a generated PDF (read access enforced per case visibility)."""
    record = db.get(ReportRecord, report_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    _get_readable_case(db, current_user, record.case_id)

    path = Path(record.storage_reference)
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Report file is no longer available",
        )
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=f"{record.report_identifier}.pdf",
    )
