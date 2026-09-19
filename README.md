# CMRS — Chain-of-Custody Management & Reporting System

A digital evidence **chain-of-custody** management system for **academic/demonstration
purposes**. CMRS records who handled digital evidence, when, and why — and makes it
possible to verify that the evidence and the audit history have **not been altered**.

> **Important:** CMRS is **tamper-evident**, not tamper-proof. It uses a **chained-hash
> audit ledger** (not a blockchain — there is no distributed consensus mechanism).

---

## What CMRS does

1. Authenticates users with JWT and enforces role-based access control (RBAC).
2. Manages digital evidence **cases**.
3. Validates and uploads digital evidence files.
4. Calculates a **SHA-256** hash of the original evidence bytes.
5. Encrypts evidence with **AES-256-GCM** before storing it outside the database.
6. Stores evidence **metadata** in PostgreSQL.
7. Tracks **evidence movement and custody**.
8. Maintains a **chained-hash audit ledger** of security-relevant actions.
9. Verifies **evidence integrity** (decrypt → re-hash → compare).
10. Verifies **ledger integrity** (reconstruct the hash chain).
11. Records user activity and extracts **behavioural features**.
12. Uses **Isolation Forest** for **AI-assisted anomaly detection** (scores and
    alerts for human review — AI never bans users, deletes files, or changes evidence).
13. Generates professional **PDF chain-of-custody reports** from database data.

## Roles

| Role | Capabilities |
| --- | --- |
| **Admin** | Manage users/roles, view everything, verify ledger, review AI alerts, generate reports, view audit logs |
| **Investigator** | Manage assigned cases, upload evidence, custody transfers, verify evidence, permitted reports |
| **Viewer** | Read-only access to permitted cases/evidence; cannot modify anything |

## Tech stack

- **Backend:** Python, FastAPI, Uvicorn, SQLAlchemy, PostgreSQL, Alembic, Pydantic,
  JWT, bcrypt, AES-256-GCM
- **AI:** scikit-learn (Isolation Forest), pandas, numpy, joblib
- **Reports:** ReportLab
- **Frontend:** React, Vite, Axios, Tailwind CSS
- **Testing:** pytest + FastAPI TestClient

## Project layout

```
CMRS/
├── backend/
│   ├── requirements.txt     # Python dependencies
│   ├── .env.example         # Environment variable template (copy to .env)
│   └── (app code added in later phases)
├── .gitignore
└── README.md
```

---

## Getting started (Phase 1)

Prerequisites: Python 3.13+ and (from Phase 3 onwards) PostgreSQL.

### 1. Create the backend virtual environment

```bat
cd m:\CMRS\backend
python -m venv .venv
```

### 2. Activate the virtual environment

```bat
.venv\Scripts\activate
```

### 3. Upgrade pip and install dependencies

```bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Verify the install

```bat
python -c "import fastapi, uvicorn, sqlalchemy, psycopg, jwt, bcrypt, cryptography, sklearn, joblib, reportlab, pytest; print('ALL_IMPORTS_OK')"
python -m pytest --version
```

You should see `ALL_IMPORTS_OK` and the pytest version.

### 5. (Later) Prepare your environment file

When we reach the phase that needs secrets, create your real `.env`:

```bat
copy .env.example .env
```

Fill in real secret values. **Never commit `.env`.**

---

## Session status

| Phase | Description | Status |
| --- | --- | --- |
| 1 | Project setup | ✔ In progress |
| 2–24 | Remaining phases | To be built incrementally |

## Security notes

- **No secrets are hard-coded.** Everything comes from environment variables / `.env`.
- **Never commit `.env`.**

---

*CMRS is a demonstration system. It aims to make tampering evident — it cannot make
tampering impossible.*