"""Authentication, session management and account security endpoints."""

from datetime import timedelta
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from server.db import get_db
from server.deps import ACCESS_COOKIE, REFRESH_COOKIE, AuthContext, client_ip, get_current_context
from server.models import AuthSession, RevokedToken, User
from server.schemas import LoginRequest, RegisterRequest, UserOut
from server.security import tokens
from server.security.csrf import CSRF_COOKIE, generate_csrf_token, require_csrf
from server.security.passwords import hash_password, verify_password
from server.services.audit import raise_alert, record
from server.utils import device_label, iso, new_id, utcnow

router = APIRouter(prefix="/api/auth", tags=["auth"])


@lru_cache
def _dummy_hash() -> str:
    return hash_password("timing-equalisation-value-1!")


def _set_auth_cookies(response: Response, settings, access: str, refresh: str, csrf: str) -> None:
    common = {"httponly": True, "samesite": "lax", "secure": settings.cookie_secure}
    response.set_cookie(ACCESS_COOKIE, access, max_age=settings.access_token_minutes * 60,
                        path="/", **common)
    response.set_cookie(REFRESH_COOKIE, refresh, max_age=settings.refresh_token_days * 86400,
                        path="/api/auth", **common)
    response.set_cookie(CSRF_COOKIE, csrf, max_age=settings.refresh_token_days * 86400,
                        httponly=False, samesite="lax", secure=settings.cookie_secure, path="/")


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path="/api/auth")
    response.delete_cookie(CSRF_COOKIE, path="/")


def _issue_session(db: Session, request: Request, user: User, settings) -> tuple[AuthSession, str, str]:
    now = utcnow()
    session_id = new_id("sess")
    ip = client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:400]
    session = AuthSession(
        id=session_id,
        user_id=user.id,
        ip=ip,
        last_ip=ip,
        user_agent=user_agent,
        last_user_agent=user_agent,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(days=settings.refresh_token_days),
    )
    db.add(session)

    access, _, _ = tokens.create_access_token(
        request.app.state.secret_key, user.id, session_id, user.role,
        timedelta(minutes=settings.access_token_minutes),
    )
    refresh, refresh_jti, _ = tokens.create_refresh_token(
        request.app.state.secret_key, user.id, session_id, user.role,
        timedelta(days=settings.refresh_token_days),
    )
    session.refresh_jti_hash = tokens.hash_jti(refresh_jti)
    return session, access, refresh


@router.get("/csrf")
def issue_csrf(request: Request, response: Response):
    token = request.cookies.get(CSRF_COOKIE) or generate_csrf_token()
    response.set_cookie(
        CSRF_COOKIE, token, max_age=request.app.state.settings.refresh_token_days * 86400,
        httponly=False, samesite="lax", secure=request.app.state.settings.cookie_secure, path="/",
    )
    return {"csrf_token": token}


@router.post("/register", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def register(payload: RegisterRequest, request: Request, response: Response,
             db: Session = Depends(get_db)):
    settings = request.app.state.settings
    email = payload.email.lower()

    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")

    is_first_user = db.scalar(select(User).limit(1)) is None
    user = User(
        id=new_id("usr"),
        email=email,
        name=payload.name,
        password_hash=hash_password(payload.password),
        role="admin" if is_first_user else "member",
        created_at=utcnow(),
    )
    db.add(user)
    db.flush()

    session, access, refresh = _issue_session(db, request, user, settings)
    record(db, "auth.register", actor_id=user.id, target=email, ip=client_ip(request),
           detail={"role": user.role})
    _set_auth_cookies(response, settings, access, refresh, generate_csrf_token())
    return UserOut.model_validate(user)


@router.post("/login", dependencies=[Depends(require_csrf)])
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    settings = request.app.state.settings
    email = payload.email.lower()
    user = db.scalar(select(User).where(User.email == email))
    now = utcnow()

    if user and user.locked_until and user.locked_until > now:
        retry = int((user.locked_until - now).total_seconds())
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"Account temporarily locked. Try again in {retry} seconds")

    password_hash = user.password_hash if user else _dummy_hash()
    valid = verify_password(payload.password, password_hash) and user is not None

    if not valid or not user.is_active:
        if user:
            user.failed_logins += 1
            if user.failed_logins >= settings.login_max_failures:
                user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
                user.failed_logins = 0
                raise_alert(db, "Account locked after repeated failures",
                            f"{email} was locked for {settings.login_lockout_minutes} minutes.",
                            "medium", user_id=user.id)
            record(db, "auth.login_failed", actor_id=user.id, target=email, ip=client_ip(request))
            # Persist counters before the error response; the dependency rolls back on exceptions.
            db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    session, access, refresh = _issue_session(db, request, user, settings)
    record(db, "auth.login", actor_id=user.id, target=email, ip=client_ip(request),
           detail={"session_id": session.id, "device": device_label(request.headers.get("user-agent", ""))})
    _set_auth_cookies(response, settings, access, refresh, generate_csrf_token())
    return {"user": UserOut.model_validate(user), "session_id": session.id}


@router.post("/refresh", dependencies=[Depends(require_csrf)])
def refresh_session(request: Request, response: Response, db: Session = Depends(get_db)):
    settings = request.app.state.settings
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token missing")

    try:
        claims = tokens.decode_token(request.app.state.secret_key, token, tokens.REFRESH)
    except tokens.TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    session = db.get(AuthSession, claims.sid)
    if not session or session.user_id != claims.sub or session.revoked_at:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session is not valid")

    if not session.refresh_jti_hash or session.refresh_jti_hash != tokens.hash_jti(claims.jti):
        session.revoked_at = utcnow()
        raise_alert(db, "Refresh token reuse detected",
                    f"Session {session.id} presented a rotated refresh token and was revoked.",
                    "high", user_id=session.user_id, session_id=session.id)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token has been rotated")

    user = db.get(User, claims.sub)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account is not active")

    access, _, _ = tokens.create_access_token(
        request.app.state.secret_key, user.id, session.id, user.role,
        timedelta(minutes=settings.access_token_minutes),
    )
    new_refresh, new_jti, _ = tokens.create_refresh_token(
        request.app.state.secret_key, user.id, session.id, user.role,
        timedelta(days=settings.refresh_token_days),
    )
    session.refresh_jti_hash = tokens.hash_jti(new_jti)
    session.last_seen_at = utcnow()
    _set_auth_cookies(response, settings, access, new_refresh, generate_csrf_token())
    return {"user": UserOut.model_validate(user)}


@router.post("/logout", dependencies=[Depends(require_csrf)])
def logout(response: Response, context: AuthContext = Depends(get_current_context),
           db: Session = Depends(get_db)):
    context.session.revoked_at = utcnow()
    db.add(RevokedToken(jti=context.claims.jti, expires_at=context.claims.exp))
    record(db, "auth.logout", actor_id=context.user.id, target=context.user.email,
           ip=context.session.last_ip, detail={"session_id": context.session.id})
    _clear_auth_cookies(response)
    return {"status": "logged_out"}


@router.get("/me")
def me(context: AuthContext = Depends(get_current_context)):
    session = context.session
    return {
        "user": UserOut.model_validate(context.user),
        "session": {
            "id": session.id,
            "ip": session.last_ip,
            "device": device_label(session.last_user_agent),
            "created_at": iso(session.created_at),
            "risk_score": session.risk_score,
            "anomaly_score": session.anomaly_score,
            "verified": session.verified,
        },
    }


@router.get("/sessions")
def list_sessions(context: AuthContext = Depends(get_current_context), db: Session = Depends(get_db)):
    sessions = db.scalars(
        select(AuthSession).where(
            AuthSession.user_id == context.user.id, AuthSession.revoked_at.is_(None)
        ).order_by(AuthSession.last_seen_at.desc())
    ).all()
    return {
        "sessions": [
            {
                "id": item.id,
                "ip": item.last_ip,
                "device": device_label(item.last_user_agent),
                "created_at": iso(item.created_at),
                "last_seen_at": iso(item.last_seen_at),
                "verified": item.verified,
                "risk_score": item.risk_score,
                "current": item.id == context.session.id,
            }
            for item in sessions
        ]
    }


@router.post("/sessions/{session_id}/terminate", dependencies=[Depends(require_csrf)])
def terminate_own_session(session_id: str, context: AuthContext = Depends(get_current_context),
                          db: Session = Depends(get_db)):
    session = db.get(AuthSession, session_id)
    if not session or session.user_id != context.user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    session.revoked_at = utcnow()
    record(db, "auth.session_terminated", actor_id=context.user.id, target=session_id,
           ip=context.session.last_ip)
    return {"status": "terminated", "session_id": session_id}


@router.post("/password", dependencies=[Depends(require_csrf)])
def change_password(payload: dict, context: AuthContext = Depends(get_current_context),
                    db: Session = Depends(get_db)):
    current = str(payload.get("current_password", ""))
    new_password = str(payload.get("new_password", ""))
    if not verify_password(current, context.user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    from server.security.passwords import validate_password_strength

    try:
        validate_password_strength(new_password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    context.user.password_hash = hash_password(new_password)
    for session in db.scalars(
        select(AuthSession).where(
            AuthSession.user_id == context.user.id,
            AuthSession.id != context.session.id,
            AuthSession.revoked_at.is_(None),
        )
    ).all():
        session.revoked_at = utcnow()
    record(db, "auth.password_changed", actor_id=context.user.id, target=context.user.email,
           ip=context.session.last_ip)
    return {"status": "password_changed"}
