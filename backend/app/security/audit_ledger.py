"""Tamper-evident chained audit ledger helpers."""

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog

GENESIS_HASH = hashlib.sha256(b"CMRS-AUDIT-LEDGER-GENESIS").hexdigest()
_LEDGER_LOCK_KEY = 782341


def _canonical_payload(
    *,
    record_id: uuid.UUID,
    created_at: datetime,
    actor_id: uuid.UUID | None,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    result: str,
    details: dict | None,
    previous_hash: str,
) -> bytes:
    payload = {
        "id": str(record_id),
        "timestamp": created_at.astimezone(timezone.utc).isoformat(),
        "actor_id": str(actor_id) if actor_id else None,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "result": result,
        "details": details or {},
        "previous_hash": previous_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def calculate_record_hash(record: AuditLog) -> str:
    """Recalculate a record hash from its persisted ledger fields."""
    if record.previous_hash is None or record.created_at is None:
        return ""
    return hashlib.sha256(_canonical_payload(
        record_id=record.id,
        created_at=record.created_at,
        actor_id=record.actor_id,
        action=record.action,
        resource_type=record.resource_type,
        resource_id=record.resource_id,
        result=record.result,
        details=record.details,
        previous_hash=record.previous_hash,
    )).hexdigest()


def append_audit_event(
    db: Session,
    *,
    actor_id: uuid.UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    result: str = "success",
    details: dict | None = None,
) -> AuditLog:
    """Append one ledger record while serializing writers in PostgreSQL."""
    db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": _LEDGER_LOCK_KEY})
    previous = db.scalars(
        select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(1)
    ).first()
    created_at = datetime.now(timezone.utc)
    record_id = uuid.uuid4()
    previous_hash = previous.current_hash if previous else GENESIS_HASH
    current_hash = hashlib.sha256(_canonical_payload(
        record_id=record_id,
        created_at=created_at,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        details=details,
        previous_hash=previous_hash,
    )).hexdigest()
    record = AuditLog(
        id=record_id,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        details=details,
        created_at=created_at,
        updated_at=created_at,
        previous_hash=previous_hash,
        current_hash=current_hash,
    )
    db.add(record)
    db.flush()
    return record


def verify_audit_chain(db: Session) -> tuple[bool, str | None]:
    """Verify every ledger link and hash without modifying any record."""
    records = db.scalars(select(AuditLog).order_by(AuditLog.created_at, AuditLog.id)).all()
    expected_previous = GENESIS_HASH
    for record in records:
        if record.previous_hash != expected_previous:
            return False, f"Broken link at record {record.id}"
        expected_current = calculate_record_hash(record)
        if record.current_hash != expected_current:
            return False, f"Invalid hash at record {record.id}"
        expected_previous = record.current_hash
    return True, None
