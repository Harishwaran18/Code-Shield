"""Vulnerability scanning endpoints."""

import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.db import get_db
from server.deps import AuthContext, client_ip, get_current_context
from server.models import RoomMember, Scan
from server.schemas import Finding, Page, ScanOut, ScanRequest, ScanSummary
from server.security.csrf import require_csrf
from server.services.audit import raise_alert, record
from server.services.scanner import scan_code
from server.utils import new_id, utcnow

router = APIRouter(tags=["scans"])


def _scan_out(scan: Scan) -> ScanOut:
    return ScanOut(
        id=scan.id,
        created_at=scan.created_at,
        language=scan.language,
        risk_score=scan.risk_score,
        highest_severity=scan.highest_severity,
        findings_count=scan.findings_count,
        findings=[Finding(**finding) for finding in json.loads(scan.findings_json)],
        code_sha256=scan.code_sha256,
        code_bytes=scan.code_bytes,
        room_id=scan.room_id,
    )


def _summary(scan: Scan) -> ScanSummary:
    return ScanSummary(
        id=scan.id,
        created_at=scan.created_at,
        language=scan.language,
        risk_score=scan.risk_score,
        highest_severity=scan.highest_severity,
        findings_count=scan.findings_count,
        code_sha256=scan.code_sha256,
    )


@router.post("/api/scans", response_model=ScanOut, dependencies=[Depends(require_csrf)])
@router.post("/scan", response_model=ScanOut, include_in_schema=False, dependencies=[Depends(require_csrf)])
async def create_scan(payload: ScanRequest, request: Request,
                      context: AuthContext = Depends(get_current_context),
                      db: Session = Depends(get_db)):
    settings = request.app.state.settings
    size = len(payload.code.encode("utf-8"))
    if size > settings.max_code_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"Code exceeds the {settings.max_code_bytes} byte limit")

    if payload.room_id:
        membership = db.scalar(select(RoomMember).where(
            RoomMember.room_id == payload.room_id, RoomMember.user_id == context.user.id
        ))
        if not membership:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not a member of this room")

    result = await run_in_threadpool(
        scan_code, payload.code, payload.language, settings.scan_timeout_seconds
    )

    scan = Scan(
        id=new_id("scn"),
        user_id=context.user.id,
        room_id=payload.room_id,
        language=payload.language,
        code_sha256=hashlib.sha256(payload.code.encode("utf-8")).hexdigest(),
        code_bytes=size,
        findings_count=result["findings_count"],
        highest_severity=result["highest_severity"],
        risk_score=result["risk_score"],
        findings_json=json.dumps(result["findings"]),
        created_at=utcnow(),
    )
    db.add(scan)
    context.session.scans += 1
    context.session.payload_bytes += size

    record(db, "scan.created", actor_id=context.user.id, target=scan.id, ip=client_ip(request),
           detail={"risk_score": scan.risk_score, "severity": scan.highest_severity,
                   "findings": scan.findings_count, "language": scan.language})

    if scan.highest_severity == "critical":
        raise_alert(db, "Critical vulnerability found in submitted code",
                    f"Scan {scan.id} reported {scan.findings_count} findings "
                    f"(risk {scan.risk_score}/100) for {context.user.email}.",
                    "critical", user_id=context.user.id, session_id=context.session.id)

    return _scan_out(scan)


@router.get("/api/scans", response_model=Page)
def list_scans(limit: int = Query(default=20, ge=1, le=100),
               offset: int = Query(default=0, ge=0),
               room_id: str | None = None,
               context: AuthContext = Depends(get_current_context),
               db: Session = Depends(get_db)):
    conditions = []
    if context.user.role != "admin":
        conditions.append(Scan.user_id == context.user.id)
    if room_id:
        conditions.append(Scan.room_id == room_id)

    total = db.scalar(select(func.count()).select_from(Scan).where(*conditions)) or 0
    scans = db.scalars(
        select(Scan).where(*conditions).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page(items=[_summary(scan).model_dump() for scan in scans], total=total,
                limit=limit, offset=offset)


@router.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, context: AuthContext = Depends(get_current_context),
             db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan or (scan.user_id != context.user.id and context.user.role != "admin"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return _scan_out(scan)


@router.delete("/api/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require_csrf)])
def delete_scan(scan_id: str, context: AuthContext = Depends(get_current_context),
                db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan or (scan.user_id != context.user.id and context.user.role != "admin"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    db.delete(scan)
    record(db, "scan.deleted", actor_id=context.user.id, target=scan_id,
           ip=client_ip_from_context(context))
    return None


def client_ip_from_context(context: AuthContext) -> str:
    return context.session.last_ip or "unknown"
