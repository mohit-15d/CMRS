"""Authenticated, append-only chain-of-custody endpoints."""

import uuid
from datetime import datetime, timezone
from typing import Sequence

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.roles import ADMIN, INVESTIGATOR, VIEWER
from app.db.session import get_db
from app.models.case import Case, is_shared_with
from app.models.custody_transfer import CustodyTransfer
from app.models.evidence import Evidence
from app.models.user import User
from app.schemas.custody import CustodianOption, CustodyEventCreate, CustodyEventRead
from app.security.audit_ledger import append_audit_event

router = APIRouter(prefix="/api/evidence", tags=["custody"])


def _require_manager(current_user: User) -> None:
    if current_user.role not in (ADMIN, INVESTIGATOR):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def _get_accessible_evidence(
    db: Session,
    current_user: User,
    evidence_id: uuid.UUID,
    allow_current_custodian: bool = False,
) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    case = db.get(Case, evidence.case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    case_access = current_user.role == ADMIN or case.created_by_id == current_user.id or case.assigned_investigator_id == current_user.id
    if not case_access and current_user.role == VIEWER:
        # Explicitly shared viewers get READ-ONLY custody-history access.
        # The append endpoint is gated by _require_manager first, so a viewer
        # can never reach this helper on a write path.
        case_access = is_shared_with(db, case, current_user.id)
    if not case_access and allow_current_custodian:
        latest_event = db.scalars(
            select(CustodyTransfer)
            .where(CustodyTransfer.evidence_id == evidence.id)
            .order_by(desc(CustodyTransfer.transferred_at), desc(CustodyTransfer.id))
        ).first()
        case_access = (latest_event.new_custodian_id if latest_event else evidence.uploaded_by_id) == current_user.id
    if not case_access:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return evidence


def _history(db: Session, evidence_id: uuid.UUID) -> Sequence[CustodyTransfer]:
    return db.scalars(
        select(CustodyTransfer)
        .where(CustodyTransfer.evidence_id == evidence_id)
        .order_by(CustodyTransfer.transferred_at, CustodyTransfer.id)
    ).all()


def _read_event(db: Session, evidence: Evidence, event: CustodyTransfer) -> CustodyEventRead:
    released_by = db.get(User, event.previous_custodian_id) if event.previous_custodian_id else None
    received_by = db.get(User, event.new_custodian_id)
    authenticated_user = db.get(User, event.authorized_by_id)
    return CustodyEventRead(
        id=event.id,
        evidence_id=evidence.id,
        item_number=evidence.item_number,
        transferred_at=event.transferred_at,
        released_by=released_by.username if released_by else None,
        released_by_id=event.previous_custodian_id,
        received_by=received_by.username,
        received_by_id=event.new_custodian_id,
        comments=event.reason,
        location=event.location,
        authenticated_user=authenticated_user.username,
        authenticated_user_id=event.authorized_by_id,
        action=event.action,
        status=event.action.replace("_", " ").title(),
        purpose=event.reason,
    )


@router.get("/{evidence_id}/custody", response_model=list[CustodyEventRead])
def list_custody_events(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[CustodyEventRead]:
    """Return the immutable custody history in chronological order.

    Read access: admins, case creators, assigned reviewers (any role) and the
    current custodian (see ``_get_accessible_evidence``). Append (POST) remains
    admin/investigator-only.
    """
    try:
        evidence_uuid = uuid.UUID(evidence_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid evidence_id") from exc
    evidence = _get_accessible_evidence(db, current_user, evidence_uuid, allow_current_custodian=True)
    return [_read_event(db, evidence, event) for event in _history(db, evidence.id)]


@router.post("/{evidence_id}/custody", response_model=CustodyEventRead, status_code=status.HTTP_201_CREATED)
def create_custody_event(
    evidence_id: str,
    payload: CustodyEventCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CustodyEventRead:
    """Append one authenticated custody event; existing events cannot be edited or deleted."""
    _require_manager(current_user)
    try:
        evidence_uuid = uuid.UUID(evidence_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid evidence_id") from exc
    evidence = _get_accessible_evidence(db, current_user, evidence_uuid, allow_current_custodian=True)

    recipient = db.get(User, payload.received_by_id)
    if recipient is None or not recipient.is_active or recipient.role not in (ADMIN, INVESTIGATOR):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid custody recipient")

    history = _history(db, evidence.id)
    current_custodian_id = history[-1].new_custodian_id if history else evidence.uploaded_by_id
    if recipient.id == current_custodian_id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Recipient is already the current custodian")
    if current_user.role != ADMIN and current_user.id != current_custodian_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the current custodian may transfer evidence")

    event = CustodyTransfer(
        evidence_id=evidence.id,
        previous_custodian_id=current_custodian_id,
        new_custodian_id=recipient.id,
        authorized_by_id=current_user.id,
        action=payload.action,
        reason=payload.comments,
        location=payload.location,
        transferred_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.flush()
    append_audit_event(
        db,
        actor_id=current_user.id,
        action="CUSTODY_TRANSFER",
        resource_type="evidence",
        resource_id=str(evidence.id),
        details={"custody_event_id": str(event.id), "action": event.action, "received_by_id": str(recipient.id)},
    )
    db.commit()
    db.refresh(event)
    return _read_event(db, evidence, event)


# --------------------------------------------------------------------------
# Custody recipient dropdown (read-only support endpoint).
#
# Mounted on its own ``/api/custody`` prefix because the evidence router owns
# ``GET /api/evidence/{evidence_id}`` and is registered first, so any new
# 1-segment GET under ``/api/evidence`` would be captured as an evidence_id.
# --------------------------------------------------------------------------
recipients_router = APIRouter(prefix="/api/custody", tags=["custody"])


@recipients_router.get("/recipients", response_model=list[CustodianOption])
def list_custody_recipients(
    current_user: User = Depends(require_roles(ADMIN, INVESTIGATOR)),
    db: Session = Depends(get_db),
) -> list[CustodianOption]:
    """Return active users eligible to RECEIVE a custody transfer.

    Mirrors - but never widens - the recipient rule already enforced by
    ``create_custody_event`` (exists + is_active + role in (admin,
    investigator)), so the dropdown can only offer selections the backend
    would accept. Parameterized ORM query; only safe fields are returned.
    """
    users = db.scalars(
        select(User)
        .where(User.is_active.is_(True), User.role.in_((ADMIN, INVESTIGATOR)))
        .order_by(User.username)
    ).all()
    return [
        CustodianOption(id=user.id, username=user.username, role=user.role)
        for user in users
    ]
