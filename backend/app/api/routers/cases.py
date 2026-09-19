"""Case management routes with backend RBAC and ownership (IDOR) checks.

Access rules:
- Anyone authenticated may CREATE a case (creating case sets created_by).
- Viewers: read-only. They may only READ cases they created OR cases they are
  assigned to (assignment grants read-only review access, never write access).
- Investigators: create cases; read, update, and change status ONLY on cases
  they created OR that are assigned to them. They cannot touch other cases.
- Admin: full read + update access to every case.

IDOR prevention: every per-case access resolves the case then confirms the
caller is permitted (owner / assigned reviewer / admin). A permitted
caller is defined in ``_can_manage`` / ``_can_read``.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.roles import ADMIN, INVESTIGATOR, VIEWER
from app.db.session import get_db
from app.models.case import Case, case_viewers, is_shared_with
from app.models.user import User
from app.schemas.case import (
    CaseCreate,
    CaseRead,
    CaseUpdate,
    CaseViewerRead,
    ViewerShareRequest,
)
from app.security.audit_ledger import append_audit_event

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _404() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")


def _403() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def _get_case_or_404(db: Session, case_id: uuid.UUID) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise _404()
    return case


def _can_manage(db: Session, user: User, case: Case) -> bool:
    """True if the user may modify/manage this case (admin OR owner/investigator)."""
    if user.role == ADMIN:
        return True
    if user.role != INVESTIGATOR:
        return False
    return case.created_by_id == user.id or case.assigned_investigator_id == user.id


def _can_read(db: Session, user: User, case: Case) -> bool:
    """True if the user may view this case.

    Read access is granted to: admins; case creators; and the assigned
    reviewer (``assigned_investigator_id``), regardless of role; plus every
    active viewer the case was explicitly shared with (``case_viewers``,
    read-only). Write access keeps its own admin/investigator role gate and is
    never widened by sharing.
    """
    if user.role == ADMIN:
        return True
    if case.created_by_id == user.id or case.assigned_investigator_id == user.id:
        return True
    # Explicitly shared viewers get read-only access (never write).
    return user.role == VIEWER and is_shared_with(db, case, user.id)


@router.post("", response_model=CaseRead, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Case:
    """Create a case. The caller becomes created_by and assigned_investigator
    (for investigators) or created_by only (other roles)."""
    # An authenticated user may create a case; viewers can create read-only-held
    # cases they own, but to keep RBAC clean we require investigator/admin.
    if current_user.role not in (INVESTIGATOR, ADMIN):
        raise _403()

    duplicate = db.execute(
        select(Case).where(Case.case_number == payload.case_number)
    ).scalar_one_or_none()
    if duplicate is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Case number already exists"
        )

    case = Case(
        case_number=payload.case_number,
        title=payload.title,
        description=payload.description,
        offense=payload.offense,
        victim=payload.victim,
        suspect=payload.suspect,
        submitting_officer=payload.submitting_officer,
        location=payload.location,
        seized_at=payload.seized_at,
        status=payload.status,
        created_by_id=current_user.id,
        assigned_investigator_id=current_user.id
        if current_user.role == INVESTIGATOR
        else None,
    )
    db.add(case)
    db.flush()
    append_audit_event(
        db,
        actor_id=current_user.id,
        action="CASE_CREATED",
        resource_type="case",
        resource_id=str(case.id),
        details={"case_number": case.case_number},
    )
    db.commit()
    db.refresh(case)
    return case


@router.get("", response_model=list[CaseRead])
def list_cases(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Case]:
    """List cases the caller is allowed to see."""
    if current_user.role == ADMIN:
        stmt = select(Case).order_by(Case.created_at.desc())
    else:
        stmt = select(Case).where(
            or_(
                Case.created_by_id == current_user.id,
                Case.assigned_investigator_id == current_user.id,
                # Explicitly shared viewers (case_viewers) see the case listed.
                Case.viewers.any(User.id == current_user.id),
            )
        ).order_by(Case.created_at.desc())
    return list(db.execute(stmt).scalars())


@router.get("/{case_id}", response_model=CaseRead)
def get_case(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Case:
    """View a single case (IDOR-safe)."""
    case = _get_case_or_404(db, case_id)
    if not _can_read(db, current_user, case):
        raise _403()
    return case


@router.patch("/{case_id}", response_model=CaseRead)
def update_case(
    case_id: uuid.UUID,
    payload: CaseUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Case:
    """Update a case the caller manages (owner / assigned investigator / admin)."""
    case = _get_case_or_404(db, case_id)
    if not _can_manage(db, current_user, case):
        raise _403()

    changes = {
        k: v
        for k, v in payload.model_dump(exclude_unset=True).items()
        if v is not None
    }
    if not changes:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="At least one field must be provided",
        )
    # Validate an assigned reviewer actually exists and is active.
    if "assigned_investigator_id" in changes:
        target = db.get(User, changes["assigned_investigator_id"])
        if target is None or not target.is_active:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Assigned user not found or inactive",
            )
    for field, value in changes.items():
        setattr(case, field, value)
    append_audit_event(
        db,
        actor_id=current_user.id,
        action="CASE_UPDATED",
        resource_type="case",
        resource_id=str(case.id),
        details={"fields": sorted(changes)},
    )
    db.commit()
    db.refresh(case)
    return case


# ----------------------------------------------------------------------------
# Investigator -> Viewer case sharing (``case_viewers`` association).
#
# Sharing is ADDITIVE and READ-ONLY for the viewer: it never modifies
# ``created_by_id`` / ``assigned_investigator_id``, custody, or evidence.
# Write capability is untouched - ``_can_manage`` keeps its existing meaning,
# so viewers can never share, unshare, edit, or assign.
# ----------------------------------------------------------------------------

viewer_router = APIRouter(prefix="/api/viewers", tags=["cases"])


@viewer_router.get("", response_model=list[CaseViewerRead])
def list_shareable_viewers(
    current_user: User = Depends(require_roles(ADMIN, INVESTIGATOR)),
    db: Session = Depends(get_db),
) -> list[User]:
    """Active VIEWER accounts (id + username only) for the share dropdown.

    Mirrors the eligibility ``share_case_with_viewer`` enforces (exists +
    is_active + role == viewer). Parameterized ORM query; never exposes
    email/password-hash/token data.
    """
    return list(
        db.execute(
            select(User)
            .where(User.role == VIEWER, User.is_active.is_(True))
            .order_by(User.username)
        ).scalars()
    )


@router.get("/{case_id}/viewers", response_model=list[CaseViewerRead])
def list_case_viewers(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[User]:
    """List the viewers a case is shared with (share-management capability).

    Gated by ``_can_manage`` (admin / case owner / assigned investigator): the
    share list belongs to the sharing workflow, so a shared viewer must not be
    able to enumerate who else the case is shared with.
    """
    case = _get_case_or_404(db, case_id)
    if not _can_manage(db, current_user, case):
        raise _403()
    return list(case.viewers)


@router.post(
    "/{case_id}/viewers",
    response_model=CaseViewerRead,
    status_code=status.HTTP_201_CREATED,
)
def share_case_with_viewer(
    case_id: uuid.UUID,
    payload: ViewerShareRequest,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CaseViewerRead:
    """Share a case with an active viewer (read-only). Idempotent.

    201 when newly shared, 200 when the viewer was already shared. Only the
    case owner/assigned investigator (or an admin) may share. The target must
    be an ACTIVE user with the VIEWER role. ``created_by_id`` and
    ``assigned_investigator_id`` are never touched.
    """
    case = _get_case_or_404(db, case_id)
    if not _can_manage(db, current_user, case):
        raise _403()

    viewer = db.get(User, payload.viewer_id)
    if viewer is None or not viewer.is_active or viewer.role != VIEWER:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Viewer not found, inactive, or not a viewer role",
        )

    if not is_shared_with(db, case, viewer.id):
        db.execute(
            case_viewers.insert().values(case_id=case.id, user_id=viewer.id)
        )
        append_audit_event(
            db,
            actor_id=current_user.id,
            action="CASE_SHARED_WITH_VIEWER",
            resource_type="case",
            resource_id=str(case.id),
            details={
                "viewer_id": str(viewer.id),
                "viewer_username": viewer.username,
            },
        )
        db.commit()
        db.refresh(case)
    else:
        # Idempotent re-share: no duplicate row, no duplicate audit event.
        response.status_code = status.HTTP_200_OK
    return viewer


@router.delete(
    "/{case_id}/viewers/{viewer_id}", status_code=status.HTTP_204_NO_CONTENT
)
def revoke_case_viewer(
    case_id: uuid.UUID,
    viewer_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Revoke a viewer's read access to a case (404 when not shared)."""
    case = _get_case_or_404(db, case_id)
    if not _can_manage(db, current_user, case):
        raise _403()

    result = db.execute(
        case_viewers.delete().where(
            case_viewers.c.case_id == case.id,
            case_viewers.c.user_id == viewer_id,
        )
    )
    if result.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Viewer is not shared on this case",
        )
    append_audit_event(
        db,
        actor_id=current_user.id,
        action="CASE_UNSHARED_FROM_VIEWER",
        resource_type="case",
        resource_id=str(case.id),
        details={"viewer_id": str(viewer_id)},
    )
    db.commit()
    return None