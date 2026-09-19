"""CMRS database models.

Importing this package registers every model on ``Base.metadata`` so that
Alembic autogeneration can discover all tables. Always import models through
this package (``from app.models import Base, User, ...``).
"""

from app.models.ai_alert import AIAlert
from app.models.audit_log import AuditLog
from app.models.base import Base
from app.models.case import Case
from app.models.custody_transfer import CustodyTransfer
from app.models.evidence import Evidence
from app.models.evidence_hash import EvidenceHash
from app.models.report_record import ReportRecord
from app.models.system_log import SystemLog
from app.models.timestamp import TimestampMixin
from app.models.user import User

__all__ = [
    "AIAlert",
    "AuditLog",
    "Base",
    "Case",
    "CustodyTransfer",
    "Evidence",
    "EvidenceHash",
    "ReportRecord",
    "SystemLog",
    "TimestampMixin",
    "User",
]
