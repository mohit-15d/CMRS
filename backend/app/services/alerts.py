"""Security alert service.

Provides a central ``create_alert`` helper used by routers and other
services to raise security alerts.  Every call also writes an audit-log
entry (ALERT_CREATED) so alert creation itself is part of the tamper-evident
ledger.

Alert creation is **advisory** — the system raises alerts but a human
administrator must always review and resolve or dismiss them.  The function
never bans users, deletes evidence, or modifies audit records.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ai_alert import AIAlert
from app.security.audit_ledger import append_audit_event


def create_alert(
    db: Session,
    *,
    alert_type: str,
    severity: str,
    explanation: str,
    case_id: Optional[uuid.UUID] = None,
    evidence_id: Optional[uuid.UUID] = None,
    user_id: Optional[uuid.UUID] = None,
    score: Optional[float] = None,
    actor_id: Optional[uuid.UUID] = None,
    details: Optional[dict] = None,
    dedupe: Optional[dict] = None,
) -> AIAlert:
    """Create a security alert and audit-log the creation.

    Parameters
    ----------
    alert_type:
        One of the ``ALERT_TYPE_*`` constants from ``app.models.ai_alert``.
    severity:
        One of ``low``, ``medium``, ``high``, ``critical``.
    explanation:
        Human-readable advisory description.  Must NOT accuse users
        directly — describe the event, not a legal conclusion.
    case_id / evidence_id / user_id:
        Nullable FK references to the related entity / user.
    score:
        Optional anomaly score (only for AI-driven alerts).
    actor_id:
        The user who triggered the event (may differ from ``user_id``).
    details:
        Additional safe metadata stored for audit purposes.

    Returns
    -------
    AIAlert
        The persisted alert object (before session commit).
    """
    # Deduplication: when the caller supplies a dedupe map (alert_type plus
    # any of user_id / evidence_id / case_id), do not create a second OPEN
    # alert for the same entity/type - return the existing open alert instead.
    # This prevents unbounded alert storms for the same ongoing condition.
    if dedupe:
        existing = _find_open_alert(db, dedupe)
        if existing is not None:
            return existing

    alert = AIAlert(
        case_id=case_id,
        evidence_id=evidence_id,
        user_id=user_id,
        alert_type=alert_type,
        severity=severity,
        score=score,
        explanation=explanation,
        status="open",
    )
    db.add(alert)
    db.flush()

    # Audit-log the alert creation so it is part of the tamper-evident ledger.
    append_audit_event(
        db,
        actor_id=actor_id,
        action="ALERT_CREATED",
        resource_type="ai_alert",
        resource_id=str(alert.id),
        details={
            "alert_type": alert_type,
            "severity": severity,
            "user_id": str(user_id) if user_id else None,
            "evidence_id": str(evidence_id) if evidence_id else None,
            "case_id": str(case_id) if case_id else None,
            **(details or {}),
        },
    )

    return alert


def _find_open_alert(db: Session, identifiers: dict) -> Optional[AIAlert]:
    """Return the first OPEN alert matching the given identifiers, if any.

    ``identifiers`` may contain ``alert_type`` and any of ``user_id``,
    ``evidence_id``, ``case_id``. Only alerts with status "open" are
    considered so that a resolved/dismissed alert can be raised again later.
    """
    stmt = select(AIAlert).where(AIAlert.status == "open")
    if identifiers.get("alert_type"):
        stmt = stmt.where(AIAlert.alert_type == identifiers["alert_type"])
    if "user_id" in identifiers:
        stmt = stmt.where(AIAlert.user_id == identifiers["user_id"])
    if "evidence_id" in identifiers:
        stmt = stmt.where(AIAlert.evidence_id == identifiers["evidence_id"])
    if "case_id" in identifiers:
        stmt = stmt.where(AIAlert.case_id == identifiers["case_id"])
    return db.scalars(stmt.limit(1)).first()


def get_alert(db: Session, alert_id: uuid.UUID) -> Optional[AIAlert]:
    """Fetch a single alert by ID."""
    return db.get(AIAlert, alert_id)


def list_alerts(
    db: Session,
    *,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[AIAlert]:
    """Return a filtered list of alerts, newest first."""
    stmt = select(AIAlert).order_by(AIAlert.created_at.desc(), AIAlert.id.desc())
    if status:
        stmt = stmt.where(AIAlert.status == status)
    if severity:
        stmt = stmt.where(AIAlert.severity == severity)
    if alert_type:
        stmt = stmt.where(AIAlert.alert_type == alert_type)
    stmt = stmt.limit(limit).offset(offset)
    return list(db.execute(stmt).scalars().all())


def review_alert(
    db: Session,
    alert: AIAlert,
    *,
    status: str,
    resolution: Optional[str],
    reviewed_by_id: uuid.UUID,
) -> AIAlert:
    """Review (or resolve / dismiss) an alert.

    Sets ``reviewed_by_id`` and ``reviewed_at`` on the first non-open
    transition.  ``resolved_at`` is set when the status is ``resolved``
    or ``dismissed``.
    """
    now = datetime.now(timezone.utc)

    if alert.status == "open" and status != "open":
        alert.reviewed_by_id = reviewed_by_id
        alert.reviewed_at = now

    if status in ("resolved", "dismissed") and alert.resolved_at is None:
        alert.resolved_at = now

    alert.status = status
    if resolution is not None:
        alert.resolution = resolution

    db.add(alert)
    db.flush()
    return alert
