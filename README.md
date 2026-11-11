# CMRS — Chain-of-Custody Management & Reporting System

A digital evidence **chain-of-custody** management system for academic and demonstration
purposes. CMRS records who handled digital evidence, when, and why — and makes it possible
to verify that the evidence and the audit history have **not been altered**.

> **Important:** CMRS is **tamper-evident**, not tamper-proof. It uses a **chained-hash
> audit ledger** (not a blockchain — there is no distributed consensus mechanism).

---

## Overview

CMRS (Chain-of-Custody Management & Reporting System) is a cybersecurity /
digital-forensics application designed to manage digital evidence and maintain a
tamper-evident chain of custody. It provides:

* User authentication and role-based access control (RBAC)
* Case and digital-evidence management
* SHA-256 integrity verification of evidence at registration and on demand
* AES-256-GCM encryption of evidence at rest
* Append-only, immutable custody-transfer records
* A chained-hash audit ledger that makes tampering detectable
* AI-assisted anomaly detection (Isolation Forest) for advisory alerting
* PDF chain-of-custody report generation (ReportLab)
* A React frontend served by the FastAPI backend

CMRS is an academic/research project. It is **tamper-evident**, not tamper-proof,
and is not suitable for production forensic deployment without significant hardening.

---

## Key Features

The following features are implemented and verified in the current codebase:

### Digital Evidence Management
* Secure evidence file upload via multipart form (`POST /api/evidence/upload`)
* 25 MB file-size limit, path-traversal filename rejection, unsafe-filename rejection
* Case-scoped storage on disk; the physical storage path is never exposed through the API
* Evidence metadata (filename, MIME type, size, description, status, uploader) stored in PostgreSQL

### Chain-of-Custody Tracking
* Append-only custody-transfer records (`CustodyTransfer`) with released-by / received-by /
  authorized-by custodians, action, reason, location, and timestamp
* Custody history is immutable — existing events cannot be edited or deleted
* Only the current custodian (or an admin) may transfer evidence
* Custody-transfer recipient dropdown restricted to active admin/investigator users

### SHA-256 Integrity Verification
* SHA-256 hash of the original plaintext evidence bytes computed and stored at registration
* Integrity verification endpoint decrypts (if encrypted), re-hashes, and compares against
  the original hash — the original hash is never replaced after a mismatch
* Verification records stored separately as `verification`-type hash records
* Clear status: `INTEGRITY VERIFIED` (match) or `INTEGRITY VIOLATION` (mismatch)

### AES-256-GCM Protection
* Evidence files encrypted with AES-256-GCM (authenticated encryption) before being written to disk
* Fresh 12-byte nonce per encryption; 16-byte authentication tag verified on decryption
* Hash is computed on the **plaintext** before encryption; verification decrypts before hashing
* Missing, invalid, or wrong encryption keys fail safely — no plaintext fallback

### Role-Based Access Control (RBAC)
* Three roles: **Admin**, **Investigator**, **Viewer**
* Registration always assigns the `viewer` role (client-supplied role is ignored — no self-escalation)
* Server-side IDOR (Insecure Direct Object Reference) prevention on every per-resource access
* Admin-only routes for user management, audit-ledger verification, anomaly analysis, and alerts

### Authentication
* JWT access tokens (PyJWT, HS256) with unique `jti` (JWT ID) claim
* bcrypt password hashing (cost factor 12, 72-byte input limit)
* Register, login, current-user (`/api/auth/me`), and logout endpoints
* Login rate limiting: per-IP request throttle and per-(IP, username) lockout
* Token revocation on logout via in-memory deny-list
* Generic error messages (unknown user vs. wrong password are indistinguishable)

### Audit Logging
* Chained-hash audit ledger: every audit record links to the previous record's hash
* Genesis hash initializes the chain; `pg_advisory_xact_lock` serializes writers in PostgreSQL
* Ledger verification reconstructs the hash chain and reports `VALID` or `INVALID`
* Records login/logout, case/evidence/custody/report actions, user role changes, alert reviews, and more
* Audit records are never repaired or deleted when tampering is detected

### Anomaly Detection (AI-Assisted, Advisory Only)
* Isolation Forest (scikit-learn) trained on behavioral audit features
* Seven features: login frequency, failed login count, evidence access frequency,
  evidence access volume, unusual access time, case access pattern, transfer frequency
* Advisory output only — labels (`NORMAL`, `ANOMALOUS`, `INSUFFICIENT_DATA`) and scores
  are never used to ban users, delete files, alter evidence, or modify audit records
* Requires at least two users with audit activity; raises a `behavioral_anomaly` alert on anomalous results

### AI Security Alerts
* Alert types: `behavioral_anomaly`, `integrity_mismatch`, `evidence_not_found`,
  `excessive_failed_logins`, `audit_ledger_invalid`, `unauthorized_access_attempt`
* Severities: low, medium, high, critical
* Human-review workflow: open → reviewed → resolved | dismissed
* Deduplication prevents alert storms for the same ongoing condition
* Every alert creation is itself written to the tamper-evident audit ledger

### Evidence Transfer Tracking
* Custody transfers record the full hand-off history for each evidence item
* Transfer actions: created, received, transferred, examined, returned, stored, final_disposition
* Each transfer is audited in the chained ledger

### Report Generation
* PDF "EVIDENCE CHAIN OF CUSTODY TRACKING FORM" (A4, ReportLab) generated from live database records
* Sections: header, case information, evidence description, CMRS digital evidence information
  (SHA-256, integrity status, encryption status), chain of custody, final disposal authority,
  forensic acknowledgment
* Optional fields render as "Not Provided" — forensic information is never invented
* Report download streamed through a controlled endpoint; on-disk path never exposed
* Report generation writes a `REPORT_GENERATED` audit-ledger event

### REST API
* FastAPI backend with automatic OpenAPI docs at `/docs`
* Health check at `/api/health`
* Single-origin deployment: the built React SPA is served by FastAPI in production (no CORS required)

### Security Monitoring
* Dashboard displays open security alerts for administrators
* Security page for admin review of alerts and anomaly analysis
* Rate limiting and lockout surfaces (429 responses)

### Dashboard
* Case statistics (open / in progress / closed)
* Open security alert count (admin only)
* Recent cases table

---

## System Architecture

```text
React Frontend (Vite, React Router)
       ↓  HTTP/JSON (Bearer JWT)
FastAPI REST API (Python 3.13+)
       ↓
Authentication + RBAC (jwt_secret, bcrypt, roles)
       ↓
Service Layer (evidence, custody, alerts, anomaly, reports)
       ↓
PostgreSQL (SQLAlchemy 2.x ORM, Alembic migrations)
       ↓
Tables: users, cases, case_viewers, evidence, evidence_hashes,
        custody_transfers, audit_logs, ai_alerts,
        report_records, system_logs
       ↓
Encrypted evidence files on disk (AES-256-GCM, outside the database)
PDF reports on disk (streamed through controlled endpoint)
```

**Frontend → Backend:** The React dev server proxies `/api` to `http://127.0.0.1:8000`. In
production, FastAPI serves the built React SPA from a single origin; `/api/*` paths always
return JSON 404s, never HTML.

---

## Security Model

### Authentication

Users authenticate with username + password via `POST /api/auth/login`. Passwords are
hashed with bcrypt (cost 12) and never stored or returned in plaintext. Successful login
returns a signed JWT access token (HS256) with a unique `jti` claim and configurable
expiry (default 60 minutes). The token is presented as a Bearer header on subsequent
requests. `POST /api/auth/logout` revokes the token by adding its `jti` to an in-memory
deny-list. Registration always assigns the `viewer` role regardless of any client-supplied
role, preventing self-escalation.

### RBAC (Role-Based Access Control)

Three roles exist, enforced server-side on every protected route:

| Role | Capabilities |
|------|-------------|
| **Admin** | Full access: user management, audit-ledger verification, anomaly analysis, alert review, all cases/evidence |
| **Investigator** | Create/manage assigned cases, upload evidence, custody transfers, verify evidence, generate reports |
| **Viewer** | Read-only access to permitted cases/evidence; cannot modify anything |

Every per-resource endpoint performs an IDOR-safe check: the resource is resolved, then the
caller is confirmed as owner, assigned investigator, admin, or (for read-only) an explicitly
shared viewer. Role gating (`require_roles`, `require_admin`) is applied in FastAPI
dependencies.

### Evidence Integrity

Each evidence item's SHA-256 hash is computed on the original plaintext bytes at upload and
stored as an `original`-type `EvidenceHash`. On-demand verification (`POST /api/evidence/verify/{id}`)
decrypts the stored file (AES-256-GCM), re-computes the SHA-256, and compares against the
original hash. The original hash is never replaced after a mismatch. Verification results are
recorded as separate `verification`-type hash records with match result, verifier, and timestamp.

### Evidence Encryption (AES-256-GCM)

Evidence files are encrypted at rest with **AES-256-GCM** before being written to disk
(outside PostgreSQL). Each encryption uses a cryptographically random 12-byte nonce and
produces a 16-byte authentication tag, which is verified on decryption. The 256-bit key is
loaded from the `ENCRYPTION_KEY` environment variable.

> **Key management limitation:** This is an academic/demo implementation. The key is loaded
> from an environment variable. In production, use a dedicated key management service
> (AWS KMS, Azure Key Vault, HashiCorp Vault, or an HSM). The database itself is **not**
> encrypted — only evidence files are encrypted before storage.

### Audit Logging (Chained-Hash Ledger)

All security-relevant actions are written to the `audit_logs` table as part of a
**chained-hash audit ledger**. Each record contains `previous_hash` and `current_hash`
(SHA-256), linking to the previous record. A genesis hash initializes an empty chain.
`pg_advisory_xact_lock` serializes concurrent writers in PostgreSQL. The ledger can be
verified (`POST /api/admin/audit-ledger/verify`, admin-only) by reconstructing the entire
hash chain; tampering is detected but records are never repaired or deleted.

Audited actions include: `LOGIN`, `LOGIN_FAILURE`, `LOGOUT`, `CASE_CREATED`, `CASE_UPDATED`,
`CASE_SHARED_WITH_VIEWER`, `CASE_UNSHARED_FROM_VIEWER`, `EVIDENCE_UPLOADED`, `EVIDENCE_ACCESSED`,
`INTEGRITY_CHECK`, `INTEGRITY_MISMATCH`, `CUSTODY_TRANSFER`, `REPORT_GENERATED`,
`ALERT_CREATED`, `ALERT_REVIEWED`, `USER_ROLE_CHANGED`, `USER_DISABLED`, and others.

### Chain of Custody

Custody transfers are recorded in the `custody_transfers` table. Each record links an evidence
item to a previous custodian (nullable for the first record) and a new custodian, with an
authorized-by user, action, reason, location, and timestamp. Transfers are append-only — they
cannot be edited or deleted. Each transfer also writes a `CUSTODY_TRANSFER` event to the
chained-hash audit ledger.

---

## Chain-of-Custody Workflow

```text
Evidence Registration (case creation + file upload)
        ↓
SHA-256 hash computed on original plaintext bytes
        ↓
Evidence encrypted with AES-256-GCM and stored outside the database
        ↓
Custody Transfer (append-only: released_by → received_by, authorized_by)
        ↓
Integrity Verification (decrypt → re-hash → compare with original)
        ↓
Audit Trail (chained-hash ledger records every action)
        ↓
Report Generation (PDF chain-of-custody tracking form from live DB records)
```

---

## Anomaly Detection

CMRS includes AI-assisted behavioral anomaly detection implemented with **Isolation Forest**
(scikit-learn). It is **advisory only** — a human administrator always makes the final
decision. The AI never bans users, deletes files, alters evidence, or modifies audit records.

| Aspect | Detail |
|--------|--------|
| **Algorithm** | Isolation Forest (`n_estimators=200`, `contamination="auto"`, `random_state=42`) |
| **Input features** (7) | `login_frequency`, `failed_login_count`, `evidence_access_frequency`, `evidence_access_volume`, `unusual_access_time`, `case_access_pattern`, `transfer_frequency` |
| **Data source** | `audit_logs` table (safe metadata only — never secrets or passwords) |
| **Output** | Label: `NORMAL`, `ANOMALOUS`, or `INSUFFICIENT_DATA`; anomaly score; feature values; sample count; explanation |
| **Alerting** | An `ANOMALOUS` result raises a `behavioral_anomaly` alert (severity: medium) for admin review |
| **Requirements** | At least 2 users with audit activity; raises `INSUFFICIENT_DATA` otherwise |

This is a research prototype, not a production AI system. No real-world accuracy claims are
made.

---

## Database

CMRS uses **PostgreSQL only** (enforced by configuration validation — SQLite and other
engines are rejected). SQLAlchemy 2.x is the ORM; Alembic manages schema migrations.

Confirmed entities (10 tables):

| Entity | Purpose |
|--------|---------|
| **User** | Accounts (admin / investigator / viewer), bcrypt password hash |
| **Case** | Investigation case with forensic fields (offense, victim, suspect, submitting officer, location, seized-at, status) |
| **case_viewers** | Many-to-many read-only sharing of cases with viewers |
| **Evidence** | Digital evidence item (filename, MIME type, size, storage path, status, uploader) |
| **EvidenceHash** | SHA-256 hash records (original + verification) with match results |
| **CustodyTransfer** | Append-only chain-of-custody hand-off records |
| **AuditLog** | Chained-hash ledger of security-relevant actions |
| **AIAlert** | Security alerts (AI anomaly, integrity mismatch, failed logins, ledger invalid, unauthorized access, evidence not found) |
| **ReportRecord** | Generated PDF report metadata (identifier, generator, storage reference, status) |
| **SystemLog** | Application/system-level event logging |

Timestamps are timezone-aware UTC, generated server-side by PostgreSQL `func.now()`.

---

## API

All API paths are prefixed with `/api`. Authentication is via Bearer JWT unless noted.

### Authentication (`/api/auth`)
| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `/register` | POST | Create a user account (always `viewer` role) | Public |
| `/login` | POST | Authenticate and receive JWT access token (rate-limited) | Public |
| `/me` | GET | Return the authenticated user's public profile | Authenticated |
| `/logout` | POST | Revoke the current access token (deny-list by `jti`) | Authenticated |

### Admin (`/api/admin`)
| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `/users` | GET | List all users | Admin |
| `/users` | POST | Create a user with admin-controlled role | Admin |
| `/users/{id}` | PATCH | Update role / active status / full name | Admin |
| `/users/{id}/reset-password` | POST | Administratively reset a user's password | Admin |
| `/audit-logs` | GET | List recent audit events (filterable by action, limit) | Admin |

### Audit Ledger (`/api/admin/audit-ledger`)
| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `/verify` | POST | Verify the chained-hash audit ledger (VALID / INVALID) | Admin |

### Anomaly Detection (`/api/admin/anomaly`)
| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `/users/{id}` | POST | Analyze user behavior (Isolation Forest, advisory) | Admin |

### Alerts (`/api/admin/alerts`)
| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `` | GET | List security alerts (filter by status/severity/type, paginated) | Admin |
| `/{id}` | GET | Get a single alert | Admin |
| `/{id}/review` | PATCH | Review / resolve / dismiss an alert | Admin |

### Cases (`/api/cases`)
| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `` | POST | Create a case | Investigator / Admin |
| `` | GET | List accessible cases | Authenticated |
| `/{id}` | GET | Get a case | Role-gated (owner / assigned / admin / shared viewer) |
| `/{id}` | PATCH | Update a case | Owner / assigned investigator / admin |
| `/{id}/viewers` | GET | List case viewers (read-only sharing) | Manager |
| `/{id}/viewers` | POST | Share case with a viewer (read-only) | Manager |
| `/{id}/viewers/{viewer_id}` | DELETE | Revoke viewer access | Manager |

### Evidence (`/api/evidence`)
| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `/upload` | POST | Upload evidence file (multipart, 25 MB max) | Investigator / Admin |
| `` | GET | List evidence (filterable by case_id) | Role-gated |
| `/{id}` | GET | Evidence detail (includes original hash + latest verification) | Role-gated |
| `/{id}/verify` | POST | SHA-256 integrity verification | Investigator / Admin |

### Custody (`/api/evidence` + `/api/custody`)
| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `/{evidence_id}/custody` | POST | Append a custody-transfer event | Investigator / Admin (current custodian) |
| `/{evidence_id}/custody` | GET | List custody history | Role-gated |
| `/custody/recipients` | GET | List eligible custody recipients (active admin/investigator) | Investigator / Admin |

### Reports (`/api/reports`)
| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `/case/{id}` | POST | Generate PDF chain-of-custody report | Investigator / Admin (case owner/assigned) |
| `/case/{id}` | GET | List generated reports for a case | Role-gated (including shared viewers) |
| `/{id}/download` | GET | Stream the generated PDF | Role-gated |

### Health
| Endpoint | Method | Description | Access |
|----------|--------|-------------|--------|
| `/api/health` | GET | Service health status | Public |
| `/` | GET | Backend API status (when SPA not built) | Public |

---

## Project Structure

```text
CMRS/
├── README.md                       # This file
├── .gitignore                      # Ignores secrets, venvs, storage, reports, etc.
├── backend.env                     # LOCAL secrets (git-ignored) — DO NOT COMMIT
├── backend/.env.example            # Committable environment variable template
├── PROJECT_STATE.md                # Project stage documentation (no secrets)
├── CMRS_*.docx                     # Academic papers / audit reports (untracked)
├── experiments/                    # Experimental artifacts (untracked)
├── reports/.gitkeep                # Generated PDF reports (git-ignored contents)
├── storage/.gitkeep                # Encrypted evidence storage (git-ignored contents)
├── backend/
│   ├── alembic.ini                 # Alembic migration config (no credentials)
│   ├── migrations/
│   │   ├── env.py                  # Injects DATABASE_URL from settings (no hard-coded creds)
│   │   ├── script.py.mako
│   │   └── versions/               # 7 migration scripts (schema history)
│   ├── pyproject.toml
│   ├── requirements.txt            # Python dependencies
│   ├── scripts/check_db_connection.py
│   ├── app/
│   │   ├── main.py                 # FastAPI entry point, lifespan, SPA serving
│   │   ├── api/
│   │   │   ├── deps.py             # get_current_user, require_roles, require_admin
│   │   │   └── routers/
│   │   │       ├── auth.py         # register, login, me, logout
│   │   │       ├── admin.py        # user management, audit-logs
│   │   │       ├── audit.py        # audit-ledger verification
│   │   │       ├── ai.py           # anomaly analysis
│   │   │       ├── alerts.py       # alert list/get/review
│   │   │       ├── cases.py        # CRUD, viewer sharing
│   │   │       ├── custody.py      # custody transfers, recipients dropdown
│   │   │       ├── evidence.py     # upload, list, detail, verify
│   │   │       └── reports.py      # PDF generation, list, download
│   │   ├── core/
│   │   │   ├── config.py           # Pydantic settings from env/backend.env
│   │   │   ├── bootstrap.py        # Bootstrap admin user on startup
│   │   │   └── roles.py            # Role constants (admin, investigator, viewer)
│   │   ├── db/
│   │   │   └── session.py          # SQLAlchemy engine/session (PostgreSQL only)
│   │   ├── models/
│   │   │   ├── base.py             # Declarative base + naming conventions
│   │   │   ├── timestamp.py        # created_at / updated_at mixin
│   │   │   ├── user.py
│   │   │   ├── case.py (+ case_viewers table)
│   │   │   ├── evidence.py
│   │   │   ├── evidence_hash.py
│   │   │   ├── custody_transfer.py
│   │   │   ├── audit_log.py        # Chained-hash ledger model
│   │   │   ├── ai_alert.py         # Alert types, severities, statuses
│   │   │   ├── report_record.py
│   │   │   └── system_log.py
│   │   ├── reports/
│   │   │   └── generator.py        # ReportLab PDF chain-of-custody form
│   │   ├── schemas/                # Pydantic request/response schemas (no password_hash exposed)
│   │   ├── security/
│   │   │   ├── audit_ledger.py     # Chained-hash ledger (genesis, append, verify)
│   │   │   ├── encryption.py       # AES-256-GCM evidence encryption/decryption
│   │   │   ├── jwt.py              # JWT create/decode with jti
│   │   │   ├── password.py         # bcrypt hash/verify
│   │   │   ├── rate_limit.py       # Sliding-window login rate limiter
│   │   │   └── token_store.py      # In-memory JWT revocation deny-list
│   │   ├── services/
│   │   │   ├── anomaly_detection.py # Isolation Forest behavioral analysis
│   │   │   └── alerts.py           # Central alert creation + audit logging
│   │   └── utils/
│   ├── tests/
│   │   ├── conftest.py             # pytest fixtures (rolled-back transactions)
│   │   ├── test_admin_user_management.py
│   │   ├── test_ai_anomaly.py
│   │   ├── test_alerts.py
│   │   ├── test_assigned_viewer.py
│   │   ├── test_audit_ledger.py
│   │   ├── test_auth_api.py
│   │   ├── test_bootstrap.py
│   │   ├── test_case_viewer_share.py
│   │   ├── test_cases.py
│   │   ├── test_custody.py
│   │   ├── test_disabled_user.py
│   │   ├── test_evidence_encryption.py
│   │   ├── test_evidence_integrity.py
│   │   ├── test_evidence_reads.py
│   │   ├── test_evidence_upload.py
│   │   ├── test_jwt.py
│   │   ├── test_logout.py
│   │   ├── test_password_hashing.py
│   │   ├── test_rate_limit.py
│   │   ├── test_rbac.py
│   │   └── test_reports.py
│   └── .venv/                      # Local virtual environment (git-ignored)
└── frontend/
    ├── package.json                # React 19, Vite, React Router
    ├── vite.config.js              # Dev proxy to http://127.0.0.1:8000
    ├── index.html
    ├── src/
    │   ├── api.js                  # Fetch client with Bearer token, safe error messages
    │   ├── auth.jsx                # Auth context (login/register/logout/me)
    │   ├── App.jsx                 # Router + role-based navigation shell
    │   ├── ui.jsx                  # Shared UI primitives
    │   ├── main.jsx
    │   ├── index.css / App.css / styles.css
    │   ├── pages/                  # 12 pages (Dashboard, Cases, Evidence, ...)
    │   └── assets/
    └── node_modules/               # git-ignored
```

---

## Installation

### Prerequisites

* **Python 3.13+**
* **Node.js 18+** and **npm** (frontend)
* **PostgreSQL 14+** server (CMRS requires PostgreSQL; SQLite is not supported)
* A running PostgreSQL instance with a database and user created for CMRS

### 1. Clone the repository

```bash
git clone <your-fork-url>
cd CMRS
```

### 2. Backend setup

```bash
cd backend

# Create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Environment configuration

Copy the template and fill in your own values:

```bash
copy backend\.env.example backend.env    # Windows
# or
cp backend/.env.example backend.env      # macOS/Linux
```

Edit `backend.env` with values appropriate for your environment:

```text
DATABASE_URL=postgresql+psycopg://<user>:<password>@<host>:5432/<dbname>
JWT_SECRET=<generate-a-long-random-secret>
JWT_EXPIRE_MINUTES=60
JWT_ALGORITHM=HS256
ENCRYPTION_KEY=<64-hex-characters-for-aes-256-gcm>
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=<strong-admin-password>
```

**Never commit `backend.env`.** It is git-ignored. The committable template is
`backend/.env.example` which contains only placeholder values.

Generate a strong JWT secret and encryption key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"     # JWT_SECRET
python -c "import secrets; print(secrets.token_hex(32))"        # ENCRYPTION_KEY (64 hex chars)
```

### 4. Database setup

Ensure PostgreSQL is running and the database specified in `DATABASE_URL` exists. Run migrations:

```bash
cd backend
alembic upgrade head
```

### 5. Start the backend

```bash
cd backend
python -m uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000` with interactive docs at `/docs`.

### 6. Frontend setup

```bash
cd frontend
npm install
npm run dev          # Vite dev server (port 5173, proxies /api to backend)
```

For production, build the SPA and FastAPI will serve it from a single origin:

```bash
cd frontend
npm run build        # Outputs to frontend/dist
```

The backend mounts `frontend/dist` if present (see `app/main.py`).

---

## Environment Variables

The following variables are read by the backend (from `backend.env` or the environment).
**Never include actual values in version control.**

| Variable | Description | Required | Example (placeholder only) |
|----------|-------------|----------|---------------------------|
| `DATABASE_URL` | PostgreSQL connection string (`postgresql+psycopg://USER:PASSWORD@HOST:PORT/DBNAME`) | Yes | `postgresql+psycopg://cmrs_user:CHANGE_ME@localhost:5432/cmrs_db` |
| `JWT_SECRET` | Secret for signing JWT access tokens | Yes | `CHANGE_ME_generate_a_long_random_secret` |
| `JWT_ALGORITHM` | JWT signature algorithm | No (default `HS256`) | `HS256` |
| `JWT_EXPIRE_MINUTES` | Access token lifetime in minutes | No (default `60`) | `60` |
| `ENCRYPTION_KEY` | 256-bit AES-GCM key (64 hex characters) for evidence-at-rest encryption | Yes | `CHANGE_ME_64_HEX_CHARACTERS` |
| `LOGIN_RATELIMIT_MAX` | Max login attempts per IP per window | No (default `10`) | `10` |
| `LOGIN_RATELIMIT_WINDOW_SECONDS` | Rate-limit window in seconds | No (default `60`) | `60` |
| `LOGIN_LOCKOUT_MAX_FAILURES` | Failed logins before lockout (per IP + username) | No (default `5`) | `5` |
| `LOGIN_LOCKOUT_WINDOW_SECONDS` | Lockout window in seconds | No (default `900`) | `900` |
| `ADMIN_USERNAME` | Bootstrap admin username (optional; skipped if unset) | No | `admin` |
| `ADMIN_EMAIL` | Bootstrap admin email | No (with admin username/password) | `admin@example.com` |
| `ADMIN_PASSWORD` | Bootstrap admin password | No (with admin username/email) | `CHANGE_ME_strong_admin_password` |
| `ADMIN_FULL_NAME` | Bootstrap admin full name | No | `System Administrator` |
| `EVIDENCE_STORAGE_DIR` | Directory for encrypted evidence files (relative to backend) | No (default `../storage/encrypted`) | `./data/evidence` |
| `REPORTS_STORAGE_DIR` | Directory for generated PDF reports | No (default `../reports`) | `./reports` |

The env file lookup order is: `backend.env` (project root), then `backend/.env`, then
project-root `.env`. The first existing file wins.

---

## Testing

### Framework

* **pytest** with **FastAPI TestClient** and **httpx**
* Tests run against the configured PostgreSQL database inside a single rolled-back
  transaction per test — no data persists to the development database
* Each test receives an ephemeral encryption key (never a configured or committed secret)
* The in-memory rate limiter and token-revocation store are reset between tests

### Test command

```bash
cd backend
python -m pytest
```

### Test categories

| Category | Covered by |
|----------|-----------|
| Authentication (register/login/me/logout, JWT, token revocation) | `test_auth_api.py`, `test_jwt.py`, `test_logout.py` |
| RBAC and role enforcement | `test_rbac.py` |
| Password hashing (bcrypt) | `test_password_hashing.py` |
| Rate limiting / lockout | `test_rate_limit.py` |
| Case management and viewer sharing | `test_cases.py`, `test_case_viewer_share.py`, `test_assigned_viewer.py` |
| Evidence upload (authorization, size limits, path traversal, duplicates) | `test_evidence_upload.py` |
| SHA-256 integrity verification | `test_evidence_integrity.py` |
| AES-256-GCM encryption/decryption | `test_evidence_encryption.py` |
| Evidence reads and audit-log listing | `test_evidence_reads.py` |
| Chain-of-custody transfers | `test_custody.py` |
| Audit ledger (chained-hash verification, tamper detection) | `test_audit_ledger.py` |
| Admin user management | `test_admin_user_management.py` |
| Disabled user / bootstrap | `test_disabled_user.py`, `test_bootstrap.py` |
| Anomaly detection (Isolation Forest) | `test_ai_anomaly.py` |
| Alerts (create, list, review, resolve, dismiss) | `test_alerts.py` |
| PDF report generation and download | `test_reports.py` |

The test suite defines a census of 228 automated test items across 21 test files and 16 functional
categories. Tests run against a live PostgreSQL database inside rolled-back transactions
(historical baseline documented in `PROJECT_STATE.md` at 193 passed prior to Stages 17-21
expansion). In environments without an active PostgreSQL instance, standalone unit tests
verify JWT creation, token revocation, bcrypt hashing, and rate limiting independently (10 standalone unit tests verified passing).

---

## Demonstration (Synthetic Data Only)

The following example uses entirely synthetic demonstration data. No real evidence,
case IDs, or forensic data are used.

```text
Case ID:        CASE-DEMO-001
Case Title:     Demo Forensic Investigation
Evidence ID:    EVIDENCE-DEMO-001
Evidence Type:  Disk Image
Original Hash:  <DEMO-SHA256-ORIGINAL-HASH>
Algorithm:      SHA-256
Encryption:     AES-256-GCM (at rest)
Custody:        Investigator A → Investigator B (action: transferred)
Integrity:      INTEGRITY VERIFIED
Report ID:      COC-DEMO01-20260101000000-deadbeef
```

**Synthetic demonstration data.** Do not use real case numbers, evidence hashes,
investigator names, or forensic artifacts in this section or anywhere in the README.

---

## Security Disclaimer

> CMRS is an academic/research project designed for authorized digital-forensics and
> cybersecurity workflows. It should only be deployed and tested in environments where the
> operator has appropriate authorization. It is **tamper-evident**, not tamper-proof, and
> is not suitable for production forensic deployment without significant hardening,
> proper key management, and a security review.

---

## Limitations

The following limitations were identified during analysis of the current implementation:

* **Academic prototype** — not hardened for production forensic use
* **Key management** — the AES-256-GCM encryption key is loaded from an environment
  variable (`ENCRYPTION_KEY`); no HSM, KMS, or vault integration is configured
* **In-memory state** — rate limiting and JWT revocation are per-process; a shared store
  (e.g. Redis or database) is required for multi-worker deployments
* **PostgreSQL dependency** — SQLite and other database engines are explicitly rejected;
  a PostgreSQL server is required
* **CORS not configured** — CORS origins are documented in `.env.example` but
  `CORSMiddleware` is not applied; needed when the frontend is served from a different origin
* **Anomaly detection** — requires sufficient behavioral data (at least 2 users with
  audit activity); results are advisory and not a substitute for human investigation
* **No Docker** — no `Dockerfile` or `docker-compose.yml` is present in the repository
* **Single-process deployment** — horizontal scaling requires a shared token-revocation
  and rate-limit store

---

## Docker

No `Dockerfile` or `docker-compose.yml` is present in the repository. The project is
designed to be run directly with Python (uvicorn) and Node (Vite), with a separately
managed PostgreSQL instance. Containerization is listed as future work.

---

## Future Improvements

The following are **planned / future work** and are NOT currently implemented:

* **Docker containerization** — `Dockerfile` and `docker-compose.yml` for backend,
  frontend, and PostgreSQL
* **CORS middleware** — configure `CORSMiddleware` for cross-origin frontend deployment
* **Distributed rate limiting / revocation** — Redis- or database-backed stores for
  multi-worker deployments
* **Production key management** — integration with AWS KMS, Azure Key Vault, HashiCorp
  Vault, or an HSM for the AES-256-GCM key
* **Database encryption-at-rest** — transparent encryption of the PostgreSQL database
  itself (currently only evidence files are encrypted)
* **Email notifications** — alerts delivered via email rather than in-app only
* **Export formats** — CSV/JSON export of audit logs and custody history
* **OAuth2 / SSO** — integration with external identity providers

---

## GitHub Security Rules

This README has been reviewed to confirm it contains:

* No passwords, tokens, or API keys
* No private keys or certificates
* No personal addresses or phone numbers
* No real evidence or forensic data (all examples are synthetic)
* No real database credentials (only placeholders)
* No private IP addresses or internal hostnames
* No absolute Windows paths
* No sensitive screenshots
* No secret configuration values

---

*CMRS — Chain-of-Custody Management & Reporting System. Tamper-evident, not tamper-proof.*
