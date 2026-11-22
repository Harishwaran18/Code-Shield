"""Security dashboard, alerts and audit endpoints."""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.db import get_db
from server.deps import AuthContext, get_current_context, require_admin
from server.models import Alert, AuditEvent, AuthSession, Scan, User
from server.schemas import (
    ActivityPoint,
    AlertOut,
    DashboardOut,
    DashboardStats,
    ScanSummary,
    SessionOut,
)
from server.security.csrf import require_csrf
from server.services.audit import record
from server.utils import device_label, iso, utcnow

router = APIRouter(prefix="/api", tags=["dashboard"])


def build_dashboard_payload(db: Session, user_id: str, is_admin: bool, anomaly_engine: str,
                            current_session_id: str | None = None) -> DashboardOut:
    now = utcnow()
    active_since = now - timedelta(minutes=30)

    session_conditions = [AuthSession.revoked_at.is_(None), AuthSession.last_seen_at >= active_since]
    scan_conditions = [Scan.created_at >= now - timedelta(hours=24)]
    alert_conditions = [Alert.created_at >= now - timedelta(days=7)]
    if not is_admin:
        session_conditions.append(AuthSession.user_id == user_id)
        scan_conditions.append(Scan.user_id == user_id)
        alert_conditions.append(Alert.user_id == user_id)

    rows = db.execute(
        select(AuthSession, User).join(User, User.id == AuthSession.user_id)
        .where(*session_conditions).order_by(AuthSession.risk_score.desc()).limit(100)
    ).all()
    sessions = [
        SessionOut(
            id=session.id, user_id=member.id, user_name=member.name, ip=session.last_ip,
            device=device_label(session.last_user_agent), created_at=session.created_at,
            last_seen_at=session.last_seen_at, verified=session.verified,
            risk_score=session.risk_score, anomaly_score=session.anomaly_score,
            current=session.id == current_session_id,
        )
        for session, member in rows
    ]

    scans_24h = db.scalar(select(func.count()).select_from(Scan).where(*scan_conditions)) or 0
    findings_24h = db.scalar(
        select(func.coalesce(func.sum(Scan.findings_count), 0)).where(*scan_conditions)
    ) or 0
    critical_24h = db.scalar(
        select(func.count()).select_from(Scan).where(*scan_conditions, Scan.highest_severity == "critical")
    ) or 0

    alerts = db.scalars(
        select(Alert).where(*alert_conditions).order_by(Alert.created_at.desc()).limit(25)
    ).all()
    alerts_open = db.scalar(
        select(func.count()).select_from(Alert).where(*alert_conditions, Alert.acknowledged.is_(False))
    ) or 0

    recent_scans = db.scalars(
        select(Scan).where(*scan_conditions).order_by(Scan.created_at.desc()).limit(10)
    ).all()

    scores = [session.risk_score for session in sessions]
    distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for score in scores:
        if score >= 75:
            distribution["critical"] += 1
        elif score >= 50:
            distribution["high"] += 1
        elif score >= 25:
            distribution["medium"] += 1
        else:
            distribution["low"] += 1

    activity = []
    for hours_ago in range(11, -1, -1):
        bucket_start = (now - timedelta(hours=hours_ago)).replace(minute=0, second=0, microsecond=0)
        bucket_end = bucket_start + timedelta(hours=1)
        activity.append(ActivityPoint(
            t=iso(bucket_start) or "",
            scans=db.scalar(select(func.count()).select_from(Scan).where(
                *scan_conditions, Scan.created_at >= bucket_start, Scan.created_at < bucket_end
            )) or 0,
            alerts=db.scalar(select(func.count()).select_from(Alert).where(
                *alert_conditions, Alert.created_at >= bucket_start, Alert.created_at < bucket_end
            )) or 0,
        ))

    total_users = (db.scalar(select(func.count()).select_from(User)) or 0) if is_admin else 1

    stats = DashboardStats(
        active_sessions=len(sessions),
        total_users=total_users,
        scans_24h=scans_24h,
        findings_24h=int(findings_24h),
        critical_findings_24h=critical_24h,
        avg_risk=round(sum(scores) / len(scores), 1) if scores else 0.0,
        verified_sessions=sum(1 for session in sessions if session.verified),
        high_risk_sessions=sum(1 for score in scores if score >= 70),
        alerts_open=alerts_open,
    )

    return DashboardOut(
        stats=stats,
        sessions=sessions,
        alerts=[AlertOut.model_validate(alert) for alert in alerts],
        recent_scans=[
            ScanSummary(
                id=scan.id, created_at=scan.created_at, language=scan.language,
                risk_score=scan.risk_score, highest_severity=scan.highest_severity,
                findings_count=scan.findings_count, code_sha256=scan.code_sha256,
            )
            for scan in recent_scans
        ],
        risk_distribution=distribution,
        activity=activity,
        anomaly_engine=anomaly_engine,
    )


@router.get("/dashboard", response_model=DashboardOut)
def dashboard(request: Request, context: AuthContext = Depends(get_current_context),
              db: Session = Depends(get_db)):
    engine = request.app.state.anomaly.describe()["engine"]
    return build_dashboard_payload(
        db, context.user.id, context.user.role == "admin", engine,
        current_session_id=context.session.id,
    )


@router.post("/sessions/{session_id}/verify", dependencies=[Depends(require_csrf)])
def verify_session(session_id: str, context: AuthContext = Depends(require_admin),
                   db: Session = Depends(get_db)):
    session = db.get(AuthSession, session_id)
    if not session:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    session.verified = True
    record(db, "session.verified", actor_id=context.user.id, target=session_id,
           ip=context.session.last_ip)
    return {"status": "verified", "session_id": session_id}


@router.post("/sessions/{session_id}/terminate", dependencies=[Depends(require_csrf)])
def terminate_session(session_id: str, context: AuthContext = Depends(require_admin),
                      db: Session = Depends(get_db)):
    session = db.get(AuthSession, session_id)
    if not session:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    session.revoked_at = utcnow()
    record(db, "session.terminated", actor_id=context.user.id, target=session_id,
           ip=context.session.last_ip)
    return {"status": "terminated", "session_id": session_id}


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(limit: int = Query(default=50, ge=1, le=200),
                context: AuthContext = Depends(get_current_context),
                db: Session = Depends(get_db)):
    conditions = []
    if context.user.role != "admin":
        conditions.append(Alert.user_id == context.user.id)
    return [
        AlertOut.model_validate(alert)
        for alert in db.scalars(
            select(Alert).where(*conditions).order_by(Alert.created_at.desc()).limit(limit)
        ).all()
    ]


@router.post("/alerts/{alert_id}/ack", dependencies=[Depends(require_csrf)])
def acknowledge_alert(alert_id: str, context: AuthContext = Depends(get_current_context),
                      db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    if context.user.role != "admin" and alert.user_id != context.user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot acknowledge this alert")
    alert.acknowledged = True
    record(db, "alert.acknowledged", actor_id=context.user.id, target=alert_id,
           ip=context.session.last_ip)
    return {"status": "acknowledged", "alert_id": alert_id}


@router.get("/audit", dependencies=[Depends(require_admin)])
def audit_trail(limit: int = Query(default=100, ge=1, le=500),
                db: Session = Depends(get_db)):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)).all()
    return {
        "events": [
            {
                "id": event.id,
                "action": event.action,
                "actor_id": event.actor_id,
                "target": event.target,
                "ip": event.ip,
                "detail": event.detail_json,
                "created_at": iso(event.created_at),
            }
            for event in events
        ]
    }


@router.get("/ml/status", dependencies=[Depends(require_admin)])
def ml_status(request: Request):
    return {"anomaly": request.app.state.anomaly.describe()}
