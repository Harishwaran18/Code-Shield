"""Authentication dependencies and session risk evaluation."""

import json
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.db import get_db
from server.models import AuditEvent, AuthSession, RevokedToken, Scan, User
from server.security import tokens
from server.security.risk import combine_session_risk, session_rule_score
from server.services.audit import raise_alert
from server.utils import utcnow

ACCESS_COOKIE = "cs_access"
REFRESH_COOKIE = "cs_refresh"


@dataclass
class AuthContext:
    user: User
    session: AuthSession
    claims: tokens.TokenClaims


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def get_current_context(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    settings = request.app.state.settings
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            token = header[7:].strip()
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")

    try:
        claims = tokens.decode_token(request.app.state.secret_key, token, tokens.ACCESS)
    except tokens.TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    if db.get(RevokedToken, claims.jti):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token has been revoked")

    session = db.get(AuthSession, claims.sid)
    if not session or session.user_id != claims.sub:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session is not valid")
    if session.revoked_at:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session has been terminated")
    if session.expires_at < utcnow():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session has expired")

    user = db.get(User, claims.sub)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account is not active")

    _evaluate_session_risk(request, db, session, user, settings)
    return AuthContext(user=user, session=session, claims=claims)


def require_admin(context: AuthContext = Depends(get_current_context)) -> AuthContext:
    if context.user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator role required")
    return context


def _evaluate_session_risk(request: Request, db: Session, session: AuthSession, user: User, settings) -> None:
    now = utcnow()
    ip = client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:400]

    ip_changed = bool(session.ip and session.ip not in {"unknown", ip})
    ua_changed = bool(session.user_agent and user_agent and session.user_agent != user_agent)

    paths = json.loads(session.paths_json or "[]")
    if request.url.path not in paths:
        paths.append(request.url.path)
        paths = paths[-50:]

    minutes = max((now - session.created_at).total_seconds() / 60.0, 1.0)
    scans_last_hour = db.scalar(
        select(func.count()).select_from(Scan).where(
            Scan.user_id == user.id, Scan.created_at >= now - timedelta(hours=1)
        )
    ) or 0
    payload_kb = int(request.headers.get("content-length") or 0) / 1024.0
    admin_actions = db.scalar(
        select(func.count()).select_from(AuditEvent).where(
            AuditEvent.actor_id == user.id,
            AuditEvent.created_at >= now - timedelta(hours=1),
            AuditEvent.action.in_(("session.verified", "session.terminated", "alert.acknowledged")),
        )
    ) or 0
    hour_angle = 2 * 3.141592653589793 * (now.hour + now.minute / 60.0) / 24.0

    features = {
        "requests_per_minute": (session.requests + 1) / minutes,
        "distinct_paths": float(len(paths)),
        "failed_logins": float(user.failed_logins),
        "scans_last_hour": float(scans_last_hour),
        "payload_kb": payload_kb,
        "hour_sin": __import__("math").sin(hour_angle),
        "hour_cos": __import__("math").cos(hour_angle),
        "ua_changed": 1.0 if ua_changed else 0.0,
        "ip_changed": 1.0 if ip_changed else 0.0,
        "admin_actions": float(admin_actions),
    }

    detector = request.app.state.anomaly
    result = detector.score(features)
    risk = combine_session_risk(result["score"], session_rule_score(features))

    previous_risk = session.risk_score
    session.requests += 1
    session.last_seen_at = now
    session.last_ip = ip
    session.last_user_agent = user_agent
    session.paths_json = json.dumps(paths)
    session.distinct_paths = len(paths)
    session.anomaly_score = result["score"]
    session.risk_score = risk

    if risk >= 70 and previous_risk < 70:
        drivers = ", ".join(item["feature"] for item in result.get("drivers", [])) or "rule thresholds"
        raise_alert(
            db,
            "High session risk detected",
            f"Session {session.id} for {user.email} scored {risk:.0f}/100 "
            f"(anomaly {result['score']:.0f}, drivers: {drivers}).",
            "critical" if risk >= 85 else "high",
            user_id=user.id,
            session_id=session.id,
        )
