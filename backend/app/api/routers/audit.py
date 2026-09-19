"""Administrator-only audit ledger verification endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.ai_alert import ALERT_SEVERITY_CRITICAL, ALERT_TYPE_AUDIT_LEDGER_INVALID
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLedgerVerificationRead
from app.security.audit_ledger import verify_audit_chain
from app.services.alerts import create_alert

router = APIRouter(prefix="/api/admin/audit-ledger", tags=["audit"])


@router.post("/verify", response_model=AuditLedgerVerificationRead)
def verify_ledger(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AuditLedgerVerificationRead:
    """Verify the audit chain without repairing or deleting corrupted records."""
    valid, error = verify_audit_chain(db)
    count = db.scalar(select(func.count()).select_from(AuditLog)) or 0

    # Stage 18: If the audit ledger is invalid (corrupted / tampered),
    # raise a security alert so an administrator can investigate.
    if not valid:
        create_alert(
            db,
            alert_type=ALERT_TYPE_AUDIT_LEDGER_INVALID,
            severity=ALERT_SEVERITY_CRITICAL,
            explanation=(
                f"Audit ledger verification failed: {error}. "
                f"The chained audit hash ledger is inconsistent, which may indicate "
                f"tampering or corruption. Reviewed by: {admin_user.username}."
            ),
            actor_id=admin_user.id,
            details={"checked_records": count, "error": error},
            dedupe={"alert_type": ALERT_TYPE_AUDIT_LEDGER_INVALID},
        )
        db.commit()

    return AuditLedgerVerificationRead(
        valid=valid,
        status="AUDIT CHAIN VALID" if valid else "AUDIT CHAIN INVALID",
        checked_records=count,
        error=error,
    )
