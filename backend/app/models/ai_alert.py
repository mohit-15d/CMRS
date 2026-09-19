"""AIAlert model - security alert records.

IMPORTANT: AI in CMRS is an ASSISTANT. Alerts are advisory only; a human
administrator always makes the final decision. AI never bans users, deletes
evidence, alters evidence, or modifies audit records.

The ``AIAlert`` table stores ALL security alerts in CMRS, not only AI-driven
ones.  Alert *creation* is automated (the system raises them), but every
alert requires explicit human review before resolution.
"""

import uuid

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.timestamp import TimestampMixin

# ----- Alert statuses --------------------------------------------------------
ALERT_STATUS_OPEN = "open"
ALERT_STATUS_REVIEWED = "reviewed"
ALERT_STATUS_RESOLVED = "resolved"
ALERT_STATUS_DISMISSED = "dismissed"

#: Ordered set of valid alert-status values (used for validation).
ALERT_STATUSES = frozenset({
    ALERT_STATUS_OPEN,
    ALERT_STATUS_REVIEWED,
    ALERT_STATUS_RESOLVED,
    ALERT_STATUS_DISMISSED,
})

# ----- Severities ------------------------------------------------------------
ALERT_SEVERITY_LOW = "low"
ALERT_SEVERITY_MEDIUM = "medium"
ALERT_SEVERITY_HIGH = "high"
ALERT_SEVERITY_CRITICAL = "critical"

ALERT_SEVERITIES = frozenset({
    ALERT_SEVERITY_LOW,
    ALERT_SEVERITY_MEDIUM,
    ALERT_SEVERITY_HIGH,
    ALERT_SEVERITY_CRITICAL,
})

# ----- Alert types -----------------------------------------------------------
# AI-driven
ALERT_TYPE_AI_ANOMALY = "behavioral_anomaly"
# Evidence / integrity
ALERT_TYPE_INTEGRITY_MISMATCH = "integrity_mismatch"
ALERT_TYPE_EVIDENCE_NOT_FOUND = "evidence_not_found"
# Authentication
ALERT_TYPE_EXCESSIVE_FAILED_LOGINS = "excessive_failed_logins"
# Audit
ALERT_TYPE_AUDIT_LEDGER_INVALID = "audit_ledger_invalid"
# Access control
ALERT_TYPE_UNAUTHORIZED_ACCESS = "unauthorized_access_attempt"

#: All alert types the system can generate.
ALERT_TYPES = frozenset({
    ALERT_TYPE_AI_ANOMALY,
    ALERT_TYPE_INTEGRITY_MISMATCH,
    ALERT_TYPE_EVIDENCE_NOT_FOUND,
    ALERT_TYPE_EXCESSIVE_FAILED_LOGINS,
    ALERT_TYPE_AUDIT_LEDGER_INVALID,
    ALERT_TYPE_UNAUTHORIZED_ACCESS,
})


class AIAlert(TimestampMixin, Base):
    """A security alert raised by CMRS (AI-assisted or otherwise).

    ``score`` is the Isolation Forest anomaly score (lower = more anomalous;
    the service layer converts it to a human-readable suspicious-activity
    score).  ``score`` is nullable because non-AI alerts have no score.

    ``status`` tracks human review workflow:
        open -> reviewed -> resolved | dismissed

    Alerts are advisory only — a human administrator always makes the final
    decision on an alert.  The system never bans users, deletes evidence,
    alters evidence, or modifies audit records based on an alert.
    """

    __tablename__ = "ai_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), index=True
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL")
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    alert_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="open", index=True
    )
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when an administrator first reviewed the alert.",
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        nullable=True,
        comment="Timestamp when the alert was resolved or dismissed.",
    )
    resolution: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Administrator's resolution notes (advisory, not a finding).",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AIAlert id={self.id} type={self.alert_type!r} sev={self.severity}>"
