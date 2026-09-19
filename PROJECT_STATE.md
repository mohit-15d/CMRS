# PROJECT_STATE.md

> Current project state — verified 2026-08-27 by completion of Stage 16
> (Security Audit Logging with Chained Ledger). Only facts confirmed by inspection or successful 
> command execution are recorded. No secrets, connection URLs, or keys appear in this file.

## Completed stages

- **Project setup (Stage 1)** — backend skeleton complete and import-clean.
- **Database wiring (Stage 2)** — SQLAlchemy engine / session factory configured.
- **Data model (Stage 3)** — SQLAlchemy 2.x models for all 9 tables registered.
- **Schema migration (Stage 4)** — initial migration created and applied.
- **Database connectivity (Stage 5)** — verified via `check_db_connection.py`.
- **Authentication (Stage 6) — COMPLETE and verified**:
  - Registration, login, JWT, current-user dependency, bootstrap admin.
  - Rate limiting and logout revocation via token deny-list.
- **RBAC + application security (Stage 7) — COMPLETE and verified**:
  - Role constants and enforcement (`require_roles`, `require_admin`).
  - Admin user management with last-admin protection.
- **Case management (Stage 8) — COMPLETE and verified**:
  - CRUD endpoints for investigation cases with `require_roles` guarding.
  - Pydantic schemas (`CaseCreate`, `CaseRead`, `CaseUpdate`).
  - Case ownership and assignment enforcement (IDOR protection).
  - Assignment of investigator with access control.
- **Evidence upload (Stage 10) — COMPLETE and verified**:
  - Secure file upload at `POST /api/evidence/upload` (multipart form).
  - Investigators and admins only; case access verification required.
  - Path traversal prevention, file size limit (25 MB), unsafe filename rejection.
  - Safe case-scoped storage on disk; metadata stored without exposing physical path.
  - Tests: 7 tests covering authorization, validation, size limits, path traversal, duplicates.
- **Evidence integrity (Stage 11) — COMPLETE and verified**:
  - SHA-256 hash computed and stored at evidence registration (original hash).
  - Integrity verification endpoint at `POST /api/evidence/verify/{evidence_id}`.
  - Verification compares current file hash against original hash (no replacement after mismatch).
  - Clear status response: "INTEGRITY VERIFIED" (match) or "INTEGRITY VIOLATION" (mismatch).
  - Audit logging for all verification attempts (success/failure with match details).
  - Tests: 14 tests covering hash computation, matching/mismatching, large files, 
    repeated verification, missing files, unauthorized access, audit logs, original 
    hash immutability.
- **Evidence encryption (Stage 12) — COMPLETE and verified**:
  - AES-256-GCM encryption at rest with an enforced 32-byte key and fresh 12-byte nonce.
  - Authentication tag is preserved and verified during decryption.
  - Upload hashes original plaintext before encryption; verification decrypts before hashing.
  - Missing keys, invalid keys, wrong keys, corrupted ciphertext, and authentication failures
    fail safely without plaintext fallback.
  - Tests: 26 encryption tests plus the complete regression suite.
- **Integrity verification workflow (Stage 13) — COMPLETE and verified**:
  - Backend response includes evidence ID, filename, original/current SHA-256, algorithm,
    verification timestamp, verifier username, and match status.
  - Static frontend verification screen calls the authenticated endpoint and renders verified
    or violation states without attributing an unsupported file modifier.
  - Existing audit logging records successful and failed verification attempts; no separate
    security-alert implementation exists to invoke.
- **Digital chain of custody (Stage 14) — COMPLETE and verified**:
  - Authenticated append-only custody events record item number, date/time, released/received
    users, comments, location, action/purpose, and the authenticated actor.
  - Evidence creation records the initial custody event; custody history is returned in
    chronological order through `GET /api/evidence/{evidence_id}/custody`.
  - Transfers require evidence/case access, an active investigator/admin recipient, and the
    current custodian unless performed by an admin. No edit or delete endpoints are exposed.
  - Tests: 6 custody tests plus the complete regression suite.
- **Security audit logging (Stage 16) — COMPLETE and verified**:
  - Important authentication, case, evidence, integrity, custody, and user-status operations
    write standardized audit events with actor, entity, result, safe metadata, and chained hashes.
  - Audit records include `previous_hash` and `current_hash`; PostgreSQL advisory locking
    serializes concurrent appenders.
  - Admin-only `POST /api/admin/audit-ledger/verify` reports valid or invalid chains without
    repairing or deleting corrupted records.
  - Existing audit rows were backfilled by migration `8b7c9d1a2e3f`.
  - Tests: 11 ledger and audit-event tests plus the complete regression suite.
- **Security alerts (Stage 18) — COMPLETE and verified**:
  - Central `create_alert` service: advisory only, deduplicated (one open alert per
    type/entity), and ledger-audited via `ALERT_CREATED`.
  - Admin-only alert API: list (status/severity/type filter, limit/offset), get, and
    review/resolve/dismiss with `ALERT_REVIEWED` audit events.
  - Alert statuses: open / reviewed / resolved / dismissed; severities: low / medium /
    high / critical. Alert review is backend-RBAC-enforced (admin only).
  - Built-in event triggers: integrity mismatch and missing-evidence (evidence router),
    excessive failed logins (auth lockout), AI anomaly (ai router), audit-chain failure
    (audit router).
  - Static frontend "Security Alerts" panel: list, severity/status badges, details,
    related entity/user, review action, resolution, loading/empty/error states.
  - Migrations `9a8e7d6c5b4f` (fixed: duplicate index removed, score nullable, added
    reviewed_at/resolution) and `1e48e96df32b` (column comments) applied; `alembic check` clean.
  - Tests: 19 alert tests plus the complete regression suite.

## Current status

- **Stage 20 (React Frontend) is complete and verified.**
- Stages 1-19 complete: 193 tests pass (189 prior + 4 new read-endpoint tests for
  evidence list/detail and admin audit-log listing added for the frontend).
- The partial Stage 18 attempt that truncated `auth.py`/`evidence.py` to 0 bytes was
  repaired; both routers were restored and the full workflow (Stages 1-19) remains green.
- Stage 21+ not started.

## Stage 20 — React Frontend (complete)

- React 19 + Vite + react-router-dom v7 SPA in `frontend/` (replaces the static page
  as the primary UI; theme: cyberpunk black/neon-red/white forensic terminal).
- Pages (13 files covering all 15 required screens; integrity verification and chain
  of custody live inside Evidence Details): Login, Register, Dashboard, Cases,
  Case Details, Evidence, Evidence Details (hashes + integrity verify + custody
  timeline + append-event form), Reports (generate/download PDF), Audit Ledger
  (admin), Anomaly Detection (admin, advisory), Alerts (admin review console),
  User Management (admin), Security console (admin posture + chain verification).
- Shared infra: `src/api.js` (fetch client with JWT header + blob download),
  `src/auth.jsx` (AuthProvider: login/register/logout/me), `src/ui.jsx` (Loading,
  ErrorBox, Empty, Badge, Confirm modal with busy state), `src/index.css` theme.
- `vite.config.js` proxies `/api` -> `http://127.0.0.1:8000` (dev, no CORS needed);
  `npm run build` produces `dist/`.
- Role-based navigation is UX only; every protected page is backed by server-side
  RBAC (verified by tests: 401 unauthenticated / 403 investigator on admin routes).
- No mock data: all screens render live API responses with loading/error/empty
  states and confirmation modals for sensitive actions (verify evidence, review
  alerts, change roles, disable users, generate reports, verify ledger).
- Backend additions for the frontend: `GET /api/evidence` (list, case-scoped),
  `GET /api/evidence/{id}` (detail with original hash + latest verification),
  `GET /api/admin/audit-logs` (admin, action filter + limit). New tests in
  `backend/tests/test_evidence_reads.py`.
- Housekeeping: removed leftover committed rows from the Stage-19 smoke run in
  `cmrs_db` (case SAMPLE-STAGE19-002, its evidence/custody/report/audit rows) which
  had broken ledger-genesis assumptions in 4 tests; users preserved; ledger back to
  genesis-clean state. `npm run build` passes; full pytest suite 193 passed.


## Blockers

- **No blockers in the implemented scope.** All implemented stages are verified and tested.
- Unimplemented by design: stages 17+, broader frontend workflows, integrations.


## Database status

- **CONNECTED (verified).** PostgreSQL reachable from `backend/.venv` with the DSN loaded
  from `backend.env` (project root). `DB_CONNECT: SUCCESS` (exit code 0) from
  `scripts/check_db_connection.py`. Credentials are never stored in source files; the script
  prints a fully redacted DSN.
- Engine: SQLAlchemy 2.0.52 + psycopg 3.3.4 (PostgreSQL only; SQLite and others rejected by a
  `field_validator` on `database_url` in `app/core/config.py`).
- Key installed versions (verified via `pip list`): alembic 1.19.1, bcrypt 5.0.0,
  cryptography 50.0.0, fastapi 0.141.1, httpx 0.28.1, joblib 1.5.3, numpy 2.5.2,
  pandas 3.0.5, psycopg 3.3.4, pydantic 2.13.4, pydantic-settings 2.15.0, PyJWT 2.13.0,
  pytest 9.1.1, reportlab 5.0.1, scikit-learn 1.9.0, SQLAlchemy 2.0.52, uvicorn 0.52.4.

## Migration status

- **CONSISTENT (verified).** `alembic heads` == `alembic current` == `8b7c9d1a2e3f`
  (single head, already applied to the database).
- `alembic check` reports **"No new upgrade operations detected"** — the SQLAlchemy models
  match the live database exactly (no drift).
- Migration covers all 9 tables with deterministic FK/PK constraint names (see architecture
  decisions). No credentials in `alembic.ini` (`sqlalchemy.url` intentionally left blank;
  `migrations/env.py` injects the DSN from `app.core.config`).

## Tests

- **24 tests across 4 files, all passing** (pytest 9.1.1):
  - `tests/conftest.py` — SAVEPOINT-rollback fixture; tests never persist to `cmrs_db` (the DB
    role cannot create databases, verified earlier).
  - `tests/test_auth_api.py` — register / login / me / health integration tests
    (201 / 409 / 422 / 401 / 403).
  - `tests/test_jwt.py` — create/decode, expired, garbage, wrong-signature.
  - `tests/test_password_hashing.py` — bcrypt roundtrip, unique salts, 72-byte limits.
- Run result 2026-08-23: `24 passed, 1 warning`. The only warning is a library-level
  `StarletteDeprecationWarning` from `fastapi.testclient` (suggests `httpx2`); benign.
- Post-run DB row count: 0 (rollback verified).

## Important architecture decisions

- **PostgreSQL ONLY.** `DATABASE_URL` must start with `postgresql://` or
  `postgresql+psycopg://`; the config validator rejects any other dialect (e.g. SQLite).
- **SQLAlchemy 2.x declarative style** — `DeclarativeBase` + `Mapped`/`mapped_column`
  (`app/models/base.py`).
- **Explicit naming convention** for all constraints/indexes
  (`ix_`, `uq_`, `ck_`, `fk_`, `pk_`) so Alembic diffs are deterministic and stable.
- **UUID primary keys** everywhere; `TimestampMixin` supplies `created_at`/`updated_at`
  as `timestamptz` with DB-side `func.now()` (clock consistency centralized in PostgreSQL).
- **Credentials never in source.** `backend.env` at project root (git-ignored via `.gitignore`)
  is the env file; `migrations/env.py` injects the real DSN at runtime; `alembic.ini` has an
  empty `sqlalchemy.url`.
- **Authentication pattern (established Phase 6):**
  - bcrypt used directly (passlib avoided — passlib 1.7.4 is incompatible with
    bcrypt>=4.1); 12 rounds; 64-char password cap keeps input within bcrypt's 72-byte limit.
  - `UserPublic` schema excludes `password_hash` by construction; no hash is ever serialized.
  - `jwt_secret` is a required `SecretStr` (no default → fail-fast) masked by pydantic in
    reprs/logs; the value lives only in git-ignored `backend.env`.
  - Login returns a generic 401 for both unknown-user and wrong-password to prevent
    username enumeration.
- **Authorization pattern (Phase 7):**
  - RBAC is a dependency chain: `get_current_user` (auth) → `require_roles(...)` (authorization,
    403 on mismatch). Future routers compose `Depends(require_roles(...))` for capability gates.
  - Registration is privilege-safe: role is always forced to `viewer`; no self-promotion.
  - Login rate limits are in-memory/single-process (per-IP + per-username); a shared store is
    required behind a load balancer (documented in `app/security/rate_limit.py`).
  - Logout revocation uses a per-process in-memory deny-list keyed by `jti`; a shared store
    (Redis/DB) is needed for multi-worker revocation consistency.
  - Admin bootstrap is idempotent and fail-safe (partial config = no admin created). Emails
    must be email-validator-compatible (special-use domains like `.local` are rejected).
- **RBAC by plain-string `role`** on `users` (`admin` / `investigator` / `viewer`); enforcement
  is planned in application code. `password_hash` will store bcrypt hashes only — plaintext
  passwords are never stored or returned (per model contract).
- **Modules are thin and horizontally organized:** `api/` (routers) → `schemas/` (Pydantic) →
  `services/` (logic) → `models/` (ORM); security (JWT/bcrypt) isolated in `security/`; AI and
  report generation isolated in `ai/` and `reports/`.

## Files changed

- **Modified in Phase 6:** `backend/app/core/config.py` (JWT + rate-limit + admin-bootstrap
  settings), `backend/app/main.py` (auth + admin routers, lifespan), `backend/backend.env`
  (generated `JWT_SECRET`, `ADMIN_*`, git-ignored), `backend/.env.example` (new knobs).
- **Created in Phase 6:** `backend/app/security/{__init__,password,jwt}.py`,
  `backend/app/schemas/{__init__,auth}.py`, `backend/app/api/{__init__,deps}.py`,
  `backend/app/api/routers/{__init__,auth}.py`, `backend/tests/conftest.py`,
  `backend/tests/test_auth_api.py`, `backend/tests/test_jwt.py`,
  `backend/tests/test_password_hashing.py`.
- **Created in Phase 7:** `backend/app/core/roles.py`, `backend/app/core/bootstrap.py`,
  `backend/app/security/rate_limit.py`, `backend/app/security/token_store.py`,
  `backend/app/api/routers/admin.py`, `backend/tests/test_rbac.py`,
  `backend/tests/test_rate_limit.py`, `backend/tests/test_logout.py`,
  `backend/tests/test_bootstrap.py`.
- **Created in Stage 12:** `backend/app/security/encryption.py`,
  `backend/tests/test_evidence_encryption.py`.
- **Modified in Stage 12:** `backend/app/core/config.py`, `backend/app/api/routers/evidence.py`,
  `backend/tests/conftest.py`, `backend/tests/test_evidence_integrity.py`.
- **Created in Stage 13:** `frontend/index.html`, `frontend/styles.css`, `frontend/app.js`.
- **Modified in Stage 13:** `backend/app/schemas/evidence.py`, `backend/app/api/routers/evidence.py`,
  `backend/tests/test_evidence_integrity.py`.
- **Created in Stage 14:** `backend/app/schemas/custody.py`, `backend/app/api/routers/custody.py`,
  `backend/tests/test_custody.py`.
- **Modified in Stage 14:** `backend/app/main.py`, `backend/app/api/routers/evidence.py`,
  `frontend/index.html`, `frontend/app.js`, `frontend/styles.css`.
- **Created in Stage 16:** `backend/app/security/audit_ledger.py`, `backend/app/schemas/audit.py`,
  `backend/app/api/routers/audit.py`, `backend/migrations/versions/8b7c9d1a2e3f_add_chained_audit_hashes.py`,
  `backend/tests/test_audit_ledger.py`.
- **Modified in Stage 16:** `backend/app/models/audit_log.py`, `backend/app/main.py`,
  `backend/app/api/routers/auth.py`, `backend/app/api/routers/admin.py`,
  `backend/app/api/routers/cases.py`, `backend/app/api/routers/evidence.py`,
  `backend/app/api/routers/custody.py`, `backend/tests/test_evidence_integrity.py`.
- **Docs:** `PROJECT_STATE.md` — updated with this verified state.
- **Repaired in Stage 18:** `backend/app/api/routers/auth.py`, `backend/app/api/routers/evidence.py`
  (restored to full known-good content after a partial Stage-18 attempt truncated them to
  0 bytes), `backend/tests/conftest.py` (added `engine.dispose()` to fix PostgreSQL
  connection-slot exhaustion during full-suite runs).
- **Created in Stage 18:** `backend/app/services/alerts.py`, `backend/app/api/routers/alerts.py`,
  `backend/app/schemas/alerts.py`, `backend/tests/test_alerts.py`,
  `backend/migrations/versions/9a8e7d6c5b4f_add_security_alert_fields.py`,
  `backend/migrations/versions/1e48e96df32b_add_ai_alerts_column_comments.py`.
- **Modified in Stage 18:** `backend/app/main.py` (alerts router), `backend/app/models/ai_alert.py`
  (status/severity/type constants, `reviewed_at` timestamptz, `resolution`), 
  `backend/app/api/routers/ai.py` (dedupe), `backend/app/api/routers/audit.py` (ledger-failure
  alert with dedupe), `frontend/index.html`, `frontend/app.js`, `frontend/styles.css`.
- **Docs:** `PROJECT_STATE.md` — updated with this verified state.
- **Created in Stage 19:** `backend/app/reports/__init__.py`,
  `backend/app/reports/generator.py` (ReportLab reference-form renderer),
  `backend/app/api/routers/reports.py`, `backend/app/schemas/reports.py`,
  `backend/tests/test_reports.py` (14 tests).
- **Modified in Stage 19:** `backend/app/main.py` (reports router),
  `backend/app/core/config.py` (`reports_storage_dir`, default `../reports`).
  Report PDFs are written to the git-ignored `reports/` directory; the on-disk
  path is never exposed via the API (downloads stream through the router, which
  re-checks per-case authorization). Every generation appends a
  `REPORT_GENERATED` event to the chained audit ledger. The generated PDF
  follows the reference "EVIDENCE CHAIN OF CUSTODY TRACKING FORM": header,
  case-information block, DESCRIPTION OF EVIDENCE (Item #/Quantity/Description
  incl. Evidence ID), CMRS DIGITAL EVIDENCE INFORMATION (Evidence ID / SHA-256 /
  Integrity Status / Encryption Status / Report ID / Audit Verification),
  CHAIN OF CUSTODY (Item #/Date-Time/Released By/Received By/Comments-Location),
  FINAL DISPOSAL AUTHORITY (certification, signature/date lines, photo-ID
  Yes/No), FORENSIC ACKNOWLEDGMENT. All values come from live database records;
  unavailable optional fields render as blank or "Not Provided" — nothing is
  invented. A sample generated with real API/DB data is at
  `reports/stage19_sample_coc_report.pdf` for visual verification.

- **Stage 20 (React frontend) — COMPLETE & verified.** `frontend/` is a Vite + React 18 SPA
  (cyberpunk red/white/black theme) with 15 pages: Login, Register, Dashboard, Cases,
  Case Details, Evidence, Evidence Details, Integrity Verification, Chain of Custody,
  Audit Ledger, Anomaly Detection, Alerts, Reports, User Management, Security. Role-based
  navigation is UX only — every privileged route is enforced server-side. Backend read
  endpoints added to power it: `GET /api/evidence`, `GET /api/evidence/{id}` (with
  `original_hash` / `latest_verification`), `GET /api/admin/audit-logs` (admin, filterable).
  New tests: `backend/tests/test_evidence_reads.py` (11 tests). Dev flow: `npm run dev`
  (Vite proxy → `http://127.0.0.1:8000`); production: `npm run build` → FastAPI serves the
  built SPA (single origin, SPA fallback; `/api` 404s stay JSON).

- **Stage 21 (integration) — COMPLETE & verified.** Full end-to-end run against the real
  app/PostgreSQL/filesystem (41/41 checks PASS, self-cleaning): login → register → admin
  promotion → case → evidence upload (SHA-256 matches) → integrity verification → custody
  transfer → audit ledger + admin log listing → alerts → anomaly (advisory) → PDF report
  generation + download → 401/403/404/409/422 error surfaces → role matrix (admin /
  investigator / viewer). Centralized frontend error handling with 401 auto-logout.

- **Final audit — COMPLETE (2026-09).** Fixed a HIGH-severity runtime bug: evidence
  encryption read `os.environ["ENCRYPTION_KEY"]` only, but pydantic-settings loads
  `backend.env` into `Settings` without injecting `os.environ` — so a real uvicorn
  deployment (key supplied only via `backend.env`) failed every upload/verification with
  "ENCRYPTION_KEY environment variable is not set" (tests missed it because conftest
  monkeypatches `os.environ`). `app/security/encryption.py` now resolves the key from the
  OS environment first and falls back to `settings.encryption_key`; the two
  "missing-key" tests were updated to clear both channels (strengthened, not weakened).
  Also: removed dead imports (`deps.py` typing.Any, `admin.py`/`cases.py` unused role
  constants, `encryption.py` typing.Tuple), fixed the 12→16-byte nonce docstring drift,
  purged 961 orphaned test-residue files under `storage/encrypted/` and one orphaned
  demo PDF, and cleaned all e2e/demo rows from the dev database (users, cases, evidence,
  custody, reports; audit ledger reset to genesis — all rows were script-generated demo
  events; `verify_audit_chain` = VALID). Full suite: **193 passed, 0 failed**;
  frontend `npm run build` passes.

## Known issues

- **CORS not configured** — `.env.example` documents `CORS_ORIGINS` but the app has no
  `CORSMiddleware`; needed when the frontend is introduced.
- **Login is JSON-only** — no OAuth2-password form endpoint; Swagger "Authorize" needs manual
  Bearer entry (acceptable; an OAuth2-form token endpoint can be added if desired).
- **In-memory rate limit + revocation** — both are per-process; a shared store (Redis/DB) is
  required for multi-worker/horizontal deployments (documented; single-process is fine now).
- **Email-validator restricts bootstrap/registration emails** — special-use/reserved domains
  (e.g. `.local`) are rejected by `EmailStr`; use a real deliverable-style address (the
  configured admin now uses `@example.com`).
- **Stale documentation:** `backend/app/db/session.py` docstring still says models are "not
  defined yet"; `README.md` phase table still shows Phase 1 "In progress".
- **Warning only:** `StarletteDeprecationWarning` from `fastapi.testclient` (library-level;
  suggests `httpx2`). Benign.
- **No git repository** — `m:\CMRS` has no `.git`, so no commit could be prepared; initialize
  a repository to version the implementation.