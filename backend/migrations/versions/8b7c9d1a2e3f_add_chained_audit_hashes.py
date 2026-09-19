"""add chained hashes to audit logs

Revision ID: 8b7c9d1a2e3f
Revises: 22ce3fc32e7f
"""

import hashlib
import json
from datetime import timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "8b7c9d1a2e3f"
down_revision: Union[str, Sequence[str], None] = "22ce3fc32e7f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

GENESIS_HASH = hashlib.sha256(b"CMRS-AUDIT-LEDGER-GENESIS").hexdigest()


def _record_hash(row: dict, previous_hash: str) -> str:
    payload = {
        "id": str(row["id"]),
        "timestamp": row["created_at"].astimezone(timezone.utc).isoformat(),
        "actor_id": str(row["actor_id"]) if row["actor_id"] else None,
        "action": row["action"],
        "resource_type": row["resource_type"],
        "resource_id": row["resource_id"],
        "result": row["result"],
        "details": row["details"] or {},
        "previous_hash": previous_hash,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("previous_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_logs", sa.Column("current_hash", sa.String(length=64), nullable=True))

    connection = op.get_bind()
    rows = connection.execute(sa.text(
        "SELECT id, created_at, actor_id, action, resource_type, resource_id, result, details "
        "FROM audit_logs ORDER BY created_at, id"
    )).mappings().all()
    previous_hash = GENESIS_HASH
    for row in rows:
        current_hash = _record_hash(row, previous_hash)
        connection.execute(
            sa.text(
                "UPDATE audit_logs SET previous_hash = :previous_hash, current_hash = :current_hash "
                "WHERE id = :id"
            ),
            {"id": row["id"], "previous_hash": previous_hash, "current_hash": current_hash},
        )
        previous_hash = current_hash

    op.alter_column("audit_logs", "previous_hash", nullable=False)
    op.alter_column("audit_logs", "current_hash", nullable=False)
    op.create_unique_constraint("uq_audit_logs_current_hash", "audit_logs", ["current_hash"])


def downgrade() -> None:
    op.drop_constraint("uq_audit_logs_current_hash", "audit_logs", type_="unique")
    op.drop_column("audit_logs", "current_hash")
    op.drop_column("audit_logs", "previous_hash")
