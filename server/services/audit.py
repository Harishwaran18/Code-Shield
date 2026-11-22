"""Audit trail and alert helpers."""

import json
import logging

from sqlalchemy.orm import Session

from server.models import Alert, AuditEvent
from server.utils import new_id, utcnow

logger = logging.getLogger("codeshield.audit")


def record(db: Session, action: str, *, actor_id: str | None = None, target: str = "",
           ip: str = "", detail: dict | None = None) -> AuditEvent:
    event = AuditEvent(
        id=new_id("evt"),
        actor_id=actor_id,
        action=action,
        target=target[:160],
        ip=ip[:64],
        detail_json=json.dumps(detail or {}, default=str),
        created_at=utcnow(),
    )
    db.add(event)
    db.flush()
    logger.info("audit", extra={"action": action, "actor_id": actor_id, "target": target, "ip": ip})
    return event


def raise_alert(db: Session, title: str, message: str, severity: str = "medium", *,
                user_id: str | None = None, session_id: str | None = None) -> Alert:
    alert = Alert(
        id=new_id("alt"),
        user_id=user_id,
        session_id=session_id,
        severity=severity,
        title=title[:160],
        message=message,
        created_at=utcnow(),
    )
    db.add(alert)
    db.flush()
    logger.warning("alert", extra={"action": "alert_raised", "target": title, "actor_id": user_id})
    return alert
