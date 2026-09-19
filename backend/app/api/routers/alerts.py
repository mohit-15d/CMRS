"""Security alert management routes (RBAC: ADMIN only).

Provides endpoints for administrators to list, view, and review security
alerts raised by CMRS (integrity mismatches, excessive failed logins,
AI anomalies, audit-ledger failures, etc.).

All alerts are advisory — the system never takes punitive action based
solely on an alert.  A human administrator must always review and resolve
or dismiss every alert.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.ai_alert import AIAlert
from app.models.user import User
from app.schemas.alerts import AlertRead, AlertReview
from app.services.alerts import get_alert, list_alerts, review_alert
from app.security.audit_ledger import append_audit_event

router = APIRouter(prefix="/api/admin/alerts", tags=["alerts"])


def _to_read(db: Session, alert: AIAlert) -> AlertRead:
    """Serialize an alert, resolving the reviewer username when set."""
    reviewer = db.get(User, alert.reviewed_by_id) if alert.reviewed_by_id else None
    return AlertRead(
        id=alert.id,
        alert_type=alert.alert_type,
        severity=alert.severity,
        score=alert.score,
        explanation=alert.explanation,
        status=alert.status,
        case_id=alert.case_id,
        evidence_id=alert.evidence_id,
        user_id=alert.user_id,
        reviewed_by_id=alert.reviewed_by_id,
        reviewed_by=reviewer.username if reviewer else None,
        reviewed_at=alert.reviewed_at,
        resolved_at=alert.resolved_at,
        resolution=alert.resolution,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )


@router.get("", response_model=list[AlertRead])
def list_alerts_endpoint(
    status: str | None = None,
    severity: str | None = None,
    alert_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[AlertRead]:
    """List security alerts (admin-only), with optional filtering.

    Query parameters:
      - ``status``: open | reviewed | resolved | dismissed
      - ``severity``: low | medium | high | critical
      - ``alert_type``: e.g. integrity_mismatch, excessive_failed_logins
      - ``limit``   (default 50, max 200)
      - ``offset``  (default 0)
    """
    allowed_statuses = {"open", "reviewed", "resolved", "dismissed"}
    allowed_severities = {"low", "medium", "high", "critical"}

    if status is not None and status.strip().lower() not in allowed_statuses:
        raise HTTPException(
            status_code=422,
            detail=f"Status must be one of: {', '.join(sorted(allowed_statuses))}",
        )
    if severity is not None and severity.strip().lower() not in allowed_severities:
        raise HTTPException(
            status_code=422,
            detail=f"Severity must be one of: {', '.join(sorted(allowed_severities))}",
        )
    if limit < 1 or limit > 200:
        raise HTTPException(
            status_code=422,
            detail="limit must be between 1 and 200",
        )
    if offset < 0:
        raise HTTPException(
            status_code=422,
            detail="offset must be >= 0",
        )

    alerts = list_alerts(
        db,
        status=status.strip().lower() if status else None,
        severity=severity.strip().lower() if severity else None,
        alert_type=alert_type.strip().lower() if alert_type else None,
        limit=limit,
        offset=offset,
    )
    return [_to_read(db, alert) for alert in alerts]


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert_endpoint(
    alert_id: uuid.UUID,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AIAlert:
    """Retrieve a single alert by ID (admin-only)."""
    alert = get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return _to_read(db, alert)


@router.patch("/{alert_id}/review", response_model=AlertRead)
def review_alert_endpoint(
    alert_id: uuid.UUID,
    payload: AlertReview,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AIAlert:
    """Review, resolve, or dismiss an alert (admin-only).

    ``status`` must be one of: ``open``, ``reviewed``, ``resolved``,
    ``dismissed``.  ``resolution`` is optional advisory notes.

    The first transition from ``open`` records ``reviewed_by`` and
    ``reviewed_at``; ``resolved`` and ``dismissed`` additionally set
    ``resolved_at``.
    """
    alert = get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    was_open = alert.status == "open"

    alert = review_alert(
        db,
        alert,
        status=payload.status,
        resolution=payload.resolution,
        reviewed_by_id=admin_user.id,
    )

    # Audit-log the review action in the chained ledger.
    append_audit_event(
        db,
        actor_id=admin_user.id,
        action="ALERT_REVIEWED",
        resource_type="ai_alert",
        resource_id=str(alert.id),
        details={
            "previous_status": "open" if was_open else "(non-open)",
            "new_status": alert.status,
            "has_resolution": alert.resolution is not None,
        },
    )
    db.commit()
    db.refresh(alert)
    return _to_read(db, alert)
