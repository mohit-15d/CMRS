"""Evidence upload routes.

Stage 10 implements secure evidence upload for case-bound records. The upload
must be restricted to investigators/admins and must verify that the user is
allowed to manage the selected case before writing any file to disk.

Stage 11 adds SHA-256 integrity verification: original hash is computed and
stored at registration; verification endpoint compares current hash against
original hash, never replacing the original after a mismatch.

Stage 12 adds AES-256-GCM encryption at rest: evidence files are encrypted
before storage using AES-256-GCM. SHA-256 hash is computed on the original
plaintext for forensic integrity. Decryption is performed during verification.

Stage 18 adds advisory security alerts for integrity mismatches and missing
evidence files. Alerts never accuse or punish any user and require human
review.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.roles import ADMIN, INVESTIGATOR, VIEWER
from app.db.session import get_db
from app.models.ai_alert import (
    ALERT_TYPE_EVIDENCE_NOT_FOUND,
    ALERT_TYPE_INTEGRITY_MISMATCH,
)
from app.models.case import Case, is_shared_with
from app.models.custody_transfer import CustodyTransfer
from app.models.evidence import Evidence
from app.models.evidence_hash import EvidenceHash
from app.models.user import User
from app.schemas.evidence import (
    EvidenceCreate,
    EvidenceDetailRead,
    EvidenceHashRead,
    EvidenceRead,
    IntegrityVerificationRead,
)
from app.security.encryption import (
    decrypt_evidence,
    encrypt_evidence,
    DecryptionError,
    EncryptionError,
)
from app.security.audit_ledger import append_audit_event
from app.services.alerts import create_alert

MAX_EVIDENCE_SIZE_BYTES = 25 * 1024 * 1024

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


def _404() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")


def _403() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def _validate_case_access(db: Session, current_user: User, case_id: uuid.UUID) -> Case:
    """Validate the caller may access (read) this case.

    Read access is granted to admins, creators, and the assigned reviewer
    (any role). Every WRITE path (upload, verify) applies its own explicit
    ``ADMIN/INVESTIGATOR`` role gate before calling this, so relaxing this
    helper only widens read access for assigned users (e.g. assigned viewers).
    """
    case = db.get(Case, case_id)
    if case is None:
        raise _404()
    if current_user.role == ADMIN:
        return case
    if case.created_by_id != current_user.id and case.assigned_investigator_id != current_user.id:
        # Explicitly shared viewers (case_viewers) get READ access to the
        # shared case. Write paths apply their own ADMIN/INVESTIGATOR role
        # gate before calling this, so viewers remain read-only.
        if current_user.role != VIEWER or not is_shared_with(db, case, current_user.id):
            raise _403()
    return case


def _safe_storage_dir() -> Path:
    base = Path(settings.evidence_storage_dir)
    if not base.is_absolute():
        base = (Path(__file__).resolve().parents[2] / base).resolve()
    base.mkdir(parents=True, exist_ok=True)
    return base


def _safe_filename(original_name: str) -> str:
    raw = original_name.strip().replace("\\", "/")
    if not raw or raw in {'.', '..'}:
        raise ValueError("Invalid file name")
    parts = [part for part in raw.split('/') if part not in ('', '.')]
    if not parts or any(part == '..' for part in parts):
        raise ValueError("Path traversal is not allowed")
    candidate = parts[-1]
    if not candidate or candidate in {'.', '..'}:
        raise ValueError("Invalid file name")
    if any(ch in candidate for ch in ('<', '>', ':', '"', '|', '?', '*')):
        raise ValueError("Invalid file name")
    return candidate


def _validate_upload(file: UploadFile, binary: bytes) -> None:
    if file.filename is None or not file.filename.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File name is required")
    if not file.content_type or file.content_type.strip() == "":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File type is required")
    if len(binary) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is empty")
    if len(binary) > MAX_EVIDENCE_SIZE_BYTES:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="File exceeds the maximum allowed size")

    content_type = file.content_type.lower()
    blocked = {
        "application/x-executable",
        "application/x-msdownload",
        "application/javascript",
        "text/x-java",
        "application/x-sh",
        "application/x-bat",
        "application/x-msdos-program",
        "application/x-dosexec",
        "application/x-powershell",
    }
    if content_type in blocked:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File type is not allowed")
    if content_type.startswith("application/x-") and content_type not in {"application/octet-stream"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File type is not allowed")

@router.get("", response_model=list[EvidenceRead])
def list_evidence(
    case_id: uuid.UUID | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List evidence the caller is allowed to see.

    Role scoping mirrors case visibility: admin sees everything; every other
    role sees evidence on cases they created OR are assigned to (an assigned
    viewer therefore sees evidence read-only). Optional ``case_id`` filter is
    access-checked (IDOR-safe).
    """
    query = db.query(Evidence)
    if case_id is not None:
        _validate_case_access(db, current_user, case_id)
        query = query.filter(Evidence.case_id == case_id)
    elif current_user.role != ADMIN:
        case_filter = or_(
            Case.created_by_id == current_user.id,
            Case.assigned_investigator_id == current_user.id,
            # Explicitly shared viewers (case_viewers) see shared-case evidence.
            Case.viewers.any(User.id == current_user.id),
        )
        visible_cases = db.query(Case.id).filter(case_filter)
        query = query.filter(Evidence.case_id.in_(visible_cases))
    return query.order_by(Evidence.created_at.desc()).all()


@router.get("/{evidence_id}", response_model=EvidenceDetailRead)
def get_evidence(
    evidence_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """View evidence metadata plus integrity hash records (IDOR-safe)."""
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise _404()
    _validate_case_access(db, current_user, evidence.case_id)

    original = (
        db.query(EvidenceHash)
        .filter(EvidenceHash.evidence_id == evidence.id, EvidenceHash.hash_type == "original")
        .first()
    )
    latest_verification = (
        db.query(EvidenceHash)
        .filter(
            EvidenceHash.evidence_id == evidence.id,
            EvidenceHash.hash_type == "verification",
        )
        .order_by(EvidenceHash.verified_at.desc(), EvidenceHash.id.desc())
        .first()
    )
    payload = EvidenceDetailRead.model_validate(evidence)
    payload.original_hash = EvidenceHashRead.model_validate(original) if original else None
    payload.latest_verification = (
        EvidenceHashRead.model_validate(latest_verification) if latest_verification else None
    )
    return payload



@router.post("/upload", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
def upload_evidence(
    case_id: str = Form(...),
    item_number: int | None = Form(default=None),
    description: str | None = Form(default=None),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Evidence:
    """Upload an evidence file into the secure evidence store."""
    if current_user.role not in (ADMIN, INVESTIGATOR):
        raise _403()

    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid case_id") from exc

    case = _validate_case_access(db, current_user, case_uuid)

    payload = EvidenceCreate(
        case_id=case_uuid,
        item_number=item_number,
        description=description,
    )
    binary = file.file.read()
    file.file.close()

    _validate_upload(file, binary)

    try:
        safe_name = _safe_filename(file.filename)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    storage_dir = _safe_storage_dir()
    case_dir = (storage_dir / str(case.id)).resolve()
    case_dir.mkdir(parents=True, exist_ok=True)

    stored_name = f"{uuid.uuid4()}_{safe_name}"
    destination = case_dir / stored_name
    if destination.exists():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Evidence file already exists")

    storage_path = str(destination)
    evidence = Evidence(
        case_id=payload.case_id,
        item_number=payload.item_number,
        original_filename=safe_name,
        storage_path=storage_path,
        mime_type=file.content_type or "application/octet-stream",
        file_size=len(binary),
        description=payload.description,
        status="active",
        uploaded_by_id=current_user.id,
    )
    db.add(evidence)
    db.flush()

    # Stage 11: Compute SHA-256 hash at registration on original plaintext
    digest = hashlib.sha256(binary).hexdigest()
    original_hash = EvidenceHash(
        evidence_id=evidence.id,
        sha256_hex=digest,
        algorithm="sha256",
        hash_type="original",
    )
    db.add(original_hash)
    db.add(CustodyTransfer(
        evidence_id=evidence.id,
        previous_custodian_id=None,
        new_custodian_id=current_user.id,
        authorized_by_id=current_user.id,
        action="created",
        reason="Evidence created",
        transferred_at=datetime.now(timezone.utc),
    ))

    # Stage 12: Encrypt evidence before storage
    try:
        encrypted_binary = encrypt_evidence(binary)
    except EncryptionError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evidence encryption failed: {exc}",
        ) from exc

    destination.write_bytes(encrypted_binary)
    append_audit_event(
        db,
        actor_id=current_user.id,
        action="EVIDENCE_UPLOADED",
        resource_type="evidence",
        resource_id=str(evidence.id),
        details={"filename": safe_name, "file_size": len(binary)},
    )
    db.commit()
    db.refresh(evidence)
    return evidence

@router.post("/verify/{evidence_id}", response_model=IntegrityVerificationRead, status_code=status.HTTP_200_OK)
def verify_evidence_integrity(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IntegrityVerificationRead:
    """Verify the integrity of an evidence file against its original SHA-256 hash.

    A match means the evidence has not been modified since registration.
    A mismatch indicates tampering or corruption. The original hash is never
    replaced; only verification records are added.
    """
    if current_user.role not in (ADMIN, INVESTIGATOR):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    try:
        evidence_uuid = uuid.UUID(evidence_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid evidence_id") from exc

    evidence = db.get(Evidence, evidence_uuid)
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    case = db.get(Case, evidence.case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    if current_user.role != ADMIN:
        if case.created_by_id != current_user.id and case.assigned_investigator_id != current_user.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    if not Path(evidence.storage_path).exists():
        append_audit_event(
            db,
            actor_id=current_user.id,
            action="EVIDENCE_ACCESSED",
            resource_type="evidence",
            resource_id=str(evidence.id),
            result="failure",
            details={"reason": "Evidence file not found on disk"},
        )
        # Stage 18: advisory security alert for missing evidence on disk.
        create_alert(
            db,
            alert_type=ALERT_TYPE_EVIDENCE_NOT_FOUND,
            severity="high",
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            actor_id=current_user.id,
            explanation=(
                "Integrity verification could not be completed because the "
                "stored evidence file is missing from secure storage. This "
                "may indicate filesystem loss or tampering. Advisory only; "
                "no user is accused."
            ),
            dedupe={
                "alert_type": ALERT_TYPE_EVIDENCE_NOT_FOUND,
                "evidence_id": evidence.id,
            },
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Evidence file not found on disk")

    encrypted_binary = Path(evidence.storage_path).read_bytes()

    # Stage 12: Decrypt evidence before hashing
    try:
        binary = decrypt_evidence(encrypted_binary)
    except DecryptionError as exc:
        append_audit_event(
            db,
            actor_id=current_user.id,
            action="EVIDENCE_ACCESSED",
            resource_type="evidence",
            resource_id=str(evidence.id),
            result="failure",
            details={"reason": "Evidence decryption failed"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evidence decryption failed (possibly corrupted or authentication tag mismatch): {exc}",
        ) from exc

    current_digest = hashlib.sha256(binary).hexdigest()

    original_hash = db.query(EvidenceHash).filter(
        EvidenceHash.evidence_id == evidence.id,
        EvidenceHash.hash_type == "original",
    ).first()

    if original_hash is None:
        append_audit_event(
            db,
            actor_id=current_user.id,
            action="INTEGRITY_CHECK",
            resource_type="evidence",
            resource_id=str(evidence.id),
            result="failure",
            details={"reason": "No original hash found"},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Original hash not found")

    match = current_digest == original_hash.sha256_hex

    append_audit_event(
        db,
        actor_id=current_user.id,
        action="EVIDENCE_ACCESSED",
        resource_type="evidence",
        resource_id=str(evidence.id),
        details={"access": "integrity_verification"},
    )
    if not match:
        append_audit_event(
            db,
            actor_id=current_user.id,
            action="INTEGRITY_MISMATCH",
            resource_type="evidence",
            resource_id=str(evidence.id),
            result="failure",
            details={"reason": "Current hash differs from original hash"},
        )
        # Stage 18: advisory security alert for the integrity mismatch.
        create_alert(
            db,
            alert_type=ALERT_TYPE_INTEGRITY_MISMATCH,
            severity="critical",
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            actor_id=current_user.id,
            explanation=(
                "Evidence integrity verification failed: the current SHA-256 "
                "digest differs from the original recorded digest. This may "
                "indicate tampering or file corruption. Advisory only; the "
                "file modifier cannot be identified without further evidence."
            ),
            details={
                "original_hash": original_hash.sha256_hex,
                "current_hash": current_digest,
            },
            dedupe={
                "alert_type": ALERT_TYPE_INTEGRITY_MISMATCH,
                "evidence_id": evidence.id,
            },
        )

    verification_hash = EvidenceHash(
        evidence_id=evidence.id,
        sha256_hex=current_digest,
        algorithm="sha256",
        hash_type="verification",
        verified_at=datetime.now(timezone.utc),
        verified_by_id=current_user.id,
        match_result=match,
    )
    db.add(verification_hash)

    audit_details = {
        "match": match,
        "original_hash": original_hash.sha256_hex,
        "current_hash": current_digest,
    }
    if not match:
        audit_details["status"] = "INTEGRITY VIOLATION"
    else:
        audit_details["status"] = "INTEGRITY VERIFIED"

    append_audit_event(
        db,
        actor_id=current_user.id,
        action="INTEGRITY_CHECK",
        resource_type="evidence",
        resource_id=str(evidence.id),
        result="success" if match else "failure",
        details=audit_details,
    )
    db.commit()

    return IntegrityVerificationRead(
        evidence_id=evidence.id,
        filename=evidence.original_filename,
        match=match,
        original_hash=original_hash.sha256_hex,
        current_hash=current_digest,
        algorithm=original_hash.algorithm.upper(),
        status="INTEGRITY VERIFIED" if match else "INTEGRITY VIOLATION",
        verified_at=verification_hash.verified_at,
        verified_by=current_user.username,
        verified_by_id=current_user.id,
    )
