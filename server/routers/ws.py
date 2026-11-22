"""Real-time collaboration and dashboard WebSockets."""

import asyncio
import json
import logging
import time
from collections import defaultdict, deque

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from server.models import AuthSession, RevokedToken, Room, RoomMember, User
from server.routers.dashboard import build_dashboard_payload
from server.security import tokens
from server.utils import iso, utcnow

logger = logging.getLogger("codeshield.realtime")

router = APIRouter(tags=["realtime"])

MAX_MESSAGE_BYTES = 300_000
MAX_CODE_BYTES = 200_000
MAX_CHAT_CHARS = 2_000
MESSAGES_PER_SECOND = 40
PERSIST_INTERVAL_SECONDS = 2.0


class RoomHub:
    def __init__(self) -> None:
        self.rooms: dict[str, dict[WebSocket, dict]] = defaultdict(dict)
        self.lock = asyncio.Lock()

    async def join(self, room_id: str, websocket: WebSocket, user: dict) -> None:
        async with self.lock:
            self.rooms[room_id][websocket] = user

    async def leave(self, room_id: str, websocket: WebSocket) -> None:
        async with self.lock:
            self.rooms[room_id].pop(websocket, None)
            if not self.rooms[room_id]:
                self.rooms.pop(room_id, None)

    def participants(self, room_id: str) -> list[dict]:
        return list(self.rooms.get(room_id, {}).values())

    async def broadcast(self, room_id: str, message: dict, exclude: WebSocket | None = None) -> None:
        for connection in list(self.rooms.get(room_id, {})):
            if connection is exclude:
                continue
            try:
                await connection.send_json(message)
            except Exception:
                logger.debug("dropping unresponsive websocket", exc_info=True)
                await self.leave(room_id, connection)


def _extract_token(websocket: WebSocket) -> str | None:
    token = websocket.cookies.get("cs_access")
    if not token:
        token = websocket.query_params.get("token")
    return token


def _authenticate(websocket: WebSocket, db) -> tuple[User | None, AuthSession | None, str | None]:
    token = _extract_token(websocket)
    if not token:
        return None, None, "Authentication required"
    try:
        claims = tokens.decode_token(websocket.app.state.secret_key, token, tokens.ACCESS)
    except tokens.TokenError as exc:
        return None, None, str(exc)
    if db.get(RevokedToken, claims.jti):
        return None, None, "Token has been revoked"
    session = db.get(AuthSession, claims.sid)
    if not session or session.revoked_at or session.expires_at < utcnow():
        return None, None, "Session is not valid"
    user = db.get(User, claims.sub)
    if not user or not user.is_active:
        return None, None, "Account is not active"
    return user, session, None


def _persist_code(app, room_id: str, code: str, force: bool = False) -> None:
    state = app.state.room_persist
    now = time.monotonic()
    if not force and now - state.get(room_id, 0.0) < PERSIST_INTERVAL_SECONDS:
        return
    state[room_id] = now
    try:
        with app.state.db.session() as db:
            room = db.get(Room, room_id)
            if room:
                room.code = code
                room.updated_at = utcnow()
    except Exception:
        logger.warning("failed to persist room code", exc_info=True)


@router.websocket("/ws/rooms/{room_id}")
async def room_socket(websocket: WebSocket, room_id: str) -> None:
    app = websocket.app
    db = app.state.db.session_factory()
    try:
        user, session, error = _authenticate(websocket, db)
        if error:
            await websocket.close(code=4401, reason=error)
            return
        room = db.get(Room, room_id)
        membership = db.scalar(select(RoomMember).where(
            RoomMember.room_id == room_id, RoomMember.user_id == user.id
        ))
        if not room or not membership:
            await websocket.close(code=4403, reason="You are not a member of this room")
            return
        snapshot = {
            "type": "snapshot",
            "room": {
                "id": room.id, "name": room.name, "language": room.language,
                "code": room.code, "owner_id": room.owner_id,
            },
            "you": {"id": user.id, "name": user.name, "role": membership.role},
        }
        identity = {"id": user.id, "name": user.name, "role": membership.role}
    finally:
        db.close()

    hub: RoomHub = app.state.hub
    await websocket.accept()
    await hub.join(room_id, websocket, identity)

    await websocket.send_json(snapshot)
    await hub.broadcast(room_id, {"type": "presence", "members": hub.participants(room_id)})

    hits: deque[float] = deque()
    last_code: str | None = None
    try:
        while True:
            raw = await websocket.receive_text()
            if len(raw.encode("utf-8")) > MAX_MESSAGE_BYTES:
                continue

            now = time.monotonic()
            while hits and now - hits[0] > 1.0:
                hits.popleft()
            if len(hits) >= MESSAGES_PER_SECOND:
                await websocket.close(code=4429, reason="Message rate limit exceeded")
                break
            hits.append(now)

            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(message, dict):
                continue

            message_type = message.get("type")
            if message_type == "edit":
                code = str(message.get("code", ""))[:MAX_CODE_BYTES]
                last_code = code
                await hub.broadcast(room_id, {
                    "type": "edit", "code": code,
                    "user": {"id": identity["id"], "name": identity["name"]},
                }, exclude=websocket)
                _persist_code(app, room_id, code)
            elif message_type == "cursor":
                await hub.broadcast(room_id, {
                    "type": "cursor",
                    "user": {"id": identity["id"], "name": identity["name"]},
                    "line": int(message.get("line", 0) or 0),
                    "column": int(message.get("column", 0) or 0),
                }, exclude=websocket)
            elif message_type == "chat":
                text = str(message.get("message", "")).strip()[:MAX_CHAT_CHARS]
                if text:
                    await hub.broadcast(room_id, {
                        "type": "chat",
                        "user": {"id": identity["id"], "name": identity["name"]},
                        "message": text,
                        "at": iso(utcnow()),
                    })
            elif message_type == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.debug("room websocket closed unexpectedly", exc_info=True)
    finally:
        if last_code is not None:
            _persist_code(app, room_id, last_code, force=True)
        await hub.leave(room_id, websocket)
        await hub.broadcast(room_id, {"type": "presence", "members": hub.participants(room_id)})


@router.websocket("/ws/dashboard")
async def dashboard_socket(websocket: WebSocket) -> None:
    app = websocket.app
    db = app.state.db.session_factory()
    try:
        user, session, error = _authenticate(websocket, db)
        if error:
            await websocket.close(code=4401, reason=error)
            return
        if user.role != "admin":
            await websocket.close(code=4403, reason="Administrator role required")
            return
        user_id, session_id = user.id, session.id
    finally:
        db.close()

    await websocket.accept()
    engine = app.state.anomaly.describe()["engine"]
    try:
        while True:
            with app.state.db.session() as read_db:
                payload = build_dashboard_payload(
                    read_db, user_id, True, engine, current_session_id=session_id
                )
            await websocket.send_json(payload.model_dump(mode="json"))
            await asyncio.sleep(2)
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception:
        logger.debug("dashboard websocket closed unexpectedly", exc_info=True)
