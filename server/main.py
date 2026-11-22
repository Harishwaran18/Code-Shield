"""Application factory for the Code-Shield platform."""

import logging
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text
from starlette.exceptions import HTTPException as StarletteHTTPException

from server.config import Settings, get_settings, resolve_secret_key
from server.db import Database
from server.models import AuthSession, RevokedToken, User
from server.routers import auth, dashboard, rooms, scans, ws
from server.security.anomaly import SessionAnomalyDetector
from server.security.headers import SecurityHeadersMiddleware
from server.security.logging import RequestContextMiddleware, configure_logging
from server.security.passwords import hash_password, validate_password_strength
from server.security.rate_limit import RateLimitMiddleware
from server.services.audit import record
from server.utils import new_id, utcnow

VERSION = "2.0.0"
WEB_DIR = Path(__file__).resolve().parent.parent / "web"

ERROR_CODES = {
    400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
    409: "conflict", 413: "payload_too_large", 422: "validation_error",
    429: "rate_limited", 500: "internal_error",
}


def _seed_admin(database: Database, settings: Settings, logger: logging.Logger) -> None:
    if not (settings.admin_email and settings.admin_password):
        return
    email = settings.admin_email.lower()
    with database.session() as db:
        if db.scalar(select(User).where(User.email == email)):
            return
        try:
            validate_password_strength(settings.admin_password)
        except ValueError as exc:
            logger.warning("admin seed skipped: %s", exc)
            return
        user = User(
            id=new_id("usr"), email=email, name="Administrator",
            password_hash=hash_password(settings.admin_password), role="admin",
            created_at=utcnow(),
        )
        db.add(user)
        db.flush()
        record(db, "admin.seeded", actor_id=user.id, target=email)
        logger.info("seeded administrator account", extra={"target": email})


def _cleanup(database: Database) -> None:
    now = utcnow()
    with database.session() as db:
        for token in db.scalars(select(RevokedToken).where(RevokedToken.expires_at < now)).all():
            db.delete(token)
        for session in db.scalars(
            select(AuthSession).where(AuthSession.expires_at < now - timedelta(days=30))
        ).all():
            db.delete(session)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging("DEBUG" if settings.debug else "INFO")
    logger = logging.getLogger("codeshield")

    app = FastAPI(
        title="Code-Shield",
        description="Secure collaborative code sharing with vulnerability scanning and "
                    "ML-based session anomaly detection.",
        version=VERSION,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.secret_key = resolve_secret_key(settings)

    if settings.database_url.startswith("sqlite:///"):
        Path(settings.database_url.replace("sqlite:///", "", 1)).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.model_dir).mkdir(parents=True, exist_ok=True)

    database = Database(settings.database_url)
    database.create_all()
    app.state.db = database
    app.state.anomaly = SessionAnomalyDetector(settings.model_dir)
    app.state.anomaly.load_or_train()
    app.state.hub = ws.RoomHub()
    app.state.room_persist = {}

    _seed_admin(database, settings, logger)
    _cleanup(database)

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        limit=settings.rate_limit_per_minute,
        auth_limit=settings.auth_rate_limit_per_minute,
    )
    app.add_middleware(RequestContextMiddleware)
    if settings.origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "X-CSRF-Token", "Authorization", "X-Request-ID"],
            max_age=600,
        )

    app.include_router(auth.router)
    app.include_router(scans.router)
    app.include_router(rooms.router)
    app.include_router(dashboard.router)
    app.include_router(ws.router)

    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/api/health", tags=["system"])
    @app.get("/health", include_in_schema=False)
    def health():
        try:
            with database.session() as db:
                db.execute(text("SELECT 1"))
            database_ok = True
        except Exception:
            database_ok = False
        return {
            "status": "ok" if database_ok else "degraded",
            "version": VERSION,
            "database": "ok" if database_ok else "unavailable",
            "anomaly_engine": app.state.anomaly.describe()["engine"],
        }

    @app.get("/api/config", tags=["system"])
    def public_config():
        return {
            "app_name": settings.app_name,
            "version": VERSION,
            "registration_enabled": True,
            "anomaly_engine": app.state.anomaly.describe()["engine"],
            "max_code_bytes": settings.max_code_bytes,
        }

    def _index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-store"})

    for path in ("/", "/login", "/register", "/app", "/dashboard"):
        app.add_api_route(path, _index, methods=["GET"], include_in_schema=False)

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        if full_path.startswith(("api/", "ws/")):
            raise StarletteHTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        candidate = (WEB_DIR / full_path).resolve()
        if candidate.is_file() and WEB_DIR in candidate.parents:
            return FileResponse(candidate)
        return _index()

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": ERROR_CODES.get(exc.status_code, "error"),
                    "message": str(exc.detail),
                }
            },
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        details = [
            {
                "field": ".".join(str(part) for part in error.get("loc", []) if part not in {"body", "query", "path"}),
                "message": error.get("msg", "Invalid value"),
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Request validation failed",
                    "details": details,
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logging.getLogger("codeshield.error").exception(
            "unhandled error", extra={"path": request.url.path}
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": {"code": "internal_error", "message": "An unexpected error occurred"}},
        )

    logger.info("Code-Shield %s ready (%s)", VERSION, settings.environment)
    return app
