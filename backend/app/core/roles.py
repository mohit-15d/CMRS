"""CMRS role identifiers.

Using named constants (instead of string literals scattered through routers)
keeps role comparisons consistent and avoids typos. The values are stored as
plain strings on ``users.role``; RBAC enforcement happens in ``app.api.deps``.
"""

ADMIN = "admin"
INVESTIGATOR = "investigator"
VIEWER = "viewer"

#: Roles that may act on digital evidence (upload, custody transfers, ...).
EVIDENCE_MANAGER_ROLES = (INVESTIGATOR, ADMIN)