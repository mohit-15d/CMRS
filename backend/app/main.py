"""CMRS - Chain-of-Custody Management & Reporting System.

FastAPI application entry point.

Phase 7 (RBAC) enforces role-based access on protected routes. The app exposes
authentication (register/login/logout/current-user), an admin-only user list,
and bootstraps an optional admin user from environment configuration on
startup. Case management and evidence upload are not implemented yet.
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy.orm import Session

from app.api.routers.admin import router as admin_router
from app.api.routers.alerts import router as alerts_router
from app.api.routers.audit import router as audit_router
from app.api.routers.ai import router as ai_router
from app.api.routers.auth import router as auth_router
from app.api.routers.cases import router as cases_router
from app.api.routers.cases import viewer_router as viewer_router
from app.api.routers.custody import recipients_router as custody_recipients_router
from app.api.routers.custody import router as custody_router
from app.api.routers.evidence import router as evidence_router
from app.api.routers.reports import router as reports_router
from app.core.bootstrap import ensure_bootstrap_admin
from app.db.session import SessionLocal

#: Built React SPA (frontend/npm run build). Served by the API when present so
#: the whole application runs from a single origin (no CORS required).
_FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


class SPAStaticFiles(StaticFiles):
    """StaticFiles with client-side-routing fallback.

    Unknown non-API paths (e.g. ``/cases/123`` deep links) fall back to
    ``index.html`` so the React router can handle them. Unknown ``/api/*``
    paths keep their JSON 404 so API consumers never receive HTML.

    Note: newer Starlette versions raise ``HTTPException(404)`` from
    ``StaticFiles.get_response`` instead of returning a 404 response, so both
    behaviours are handled here.
    """

    async def get_response(self, path: str, scope):
        # Normalise separators (some Starlette versions use os.sep on Windows)
        # and strip any leading slash before the API guard.
        normalised = path.replace("\\", "/").lstrip("/")
        if normalised.startswith("api/"):
            return await super().get_response("__no_such_file__", scope)
        try:
            response = await super().get_response(normalised, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404:
                raise
            response = await super().get_response("index.html", scope)
        if response.status_code == 404:
            response = await super().get_response("index.html", scope)
        return response




@asynccontextmanager
async def lifespan(_: FastAPI):
    """Startup: create the optional bootstrap admin user (idempotent)."""
    db: Session = SessionLocal()
    try:
        ensure_bootstrap_admin(db)
    except Exception:  # noqa: BLE001 - never prevent startup for bootstrap failure
        db.rollback()
    finally:
        db.close()
    yield


app = FastAPI(
    title="CMRS - Chain-of-Custody Management & Reporting System",
    description="Digital evidence chain-of-custody management system "
    "(academic/demonstration purposes - tamper-evident, not tamper-proof).",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(audit_router)
app.include_router(ai_router)
app.include_router(cases_router)
app.include_router(viewer_router)
app.include_router(evidence_router)
app.include_router(custody_router)
app.include_router(custody_recipients_router)
app.include_router(alerts_router)
app.include_router(reports_router)


@app.get("/api/health")
def health_check():
    """Return service health status."""
    return {"status": "ok", "service": "CMRS"}


if _FRONTEND_DIST.is_dir() and (_FRONTEND_DIST / "index.html").is_file():
    # Production integration (Stage 21): serve the built React SPA from the
    # same origin. API routes registered above always take precedence, so
    # /api/* behaviour is unchanged; everything else resolves to the SPA with
    # client-side-routing fallback for deep links.
    app.mount(
        "/",
        SPAStaticFiles(directory=_FRONTEND_DIST, html=True),
        name="spa",
    )
else:
    @app.get("/")
    def root():
        """Root endpoint - confirms the CMRS backend API is running."""
        return {"message": "CMRS Backend API is running", "status": "success"}
