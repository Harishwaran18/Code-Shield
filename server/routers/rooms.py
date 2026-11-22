"""Collaboration room endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.db import get_db
from server.deps import AuthContext, get_current_context
from server.models import Room, RoomMember, User
from server.schemas import RoomCodeUpdate, RoomCreate, RoomOut
from server.security.csrf import require_csrf
from server.services.audit import record
from server.utils import new_id, utcnow

router = APIRouter(prefix="/api/rooms", tags=["rooms"])


def _membership(db: Session, room_id: str, user_id: str) -> RoomMember | None:
    return db.scalar(select(RoomMember).where(
        RoomMember.room_id == room_id, RoomMember.user_id == user_id
    ))


def _room_out(db: Session, room: Room) -> RoomOut:
    members = db.scalar(
        select(func.count()).select_from(RoomMember).where(RoomMember.room_id == room.id)
    ) or 0
    return RoomOut(
        id=room.id, name=room.name, owner_id=room.owner_id, language=room.language,
        created_at=room.created_at, updated_at=room.updated_at, members=members, code=room.code,
    )


@router.post("", response_model=RoomOut, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_room(payload: RoomCreate, context: AuthContext = Depends(get_current_context),
                db: Session = Depends(get_db)):
    room = Room(
        id=new_id("room"), name=payload.name, owner_id=context.user.id,
        language=payload.language, code="", created_at=utcnow(), updated_at=utcnow(),
    )
    db.add(room)
    db.add(RoomMember(room_id=room.id, user_id=context.user.id, role="owner", joined_at=utcnow()))
    db.flush()
    record(db, "room.created", actor_id=context.user.id, target=room.id,
           ip=context.session.last_ip, detail={"name": room.name})
    return _room_out(db, room)


@router.get("", response_model=list[RoomOut])
def list_rooms(context: AuthContext = Depends(get_current_context), db: Session = Depends(get_db)):
    rooms = db.scalars(
        select(Room).join(RoomMember, RoomMember.room_id == Room.id).where(
            RoomMember.user_id == context.user.id
        ).order_by(Room.updated_at.desc())
    ).all()
    return [_room_out(db, room) for room in rooms]


@router.get("/{room_id}", response_model=RoomOut)
def get_room(room_id: str, context: AuthContext = Depends(get_current_context),
             db: Session = Depends(get_db)):
    room = db.get(Room, room_id)
    if not room:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Room not found")
    if not _membership(db, room_id, context.user.id) and context.user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not a member of this room")
    return _room_out(db, room)


@router.post("/{room_id}/join", response_model=RoomOut, dependencies=[Depends(require_csrf)])
def join_room(room_id: str, context: AuthContext = Depends(get_current_context),
              db: Session = Depends(get_db)):
    room = db.get(Room, room_id)
    if not room:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Room not found")
    if not _membership(db, room_id, context.user.id):
        db.add(RoomMember(room_id=room_id, user_id=context.user.id, role="editor", joined_at=utcnow()))
        db.flush()
        record(db, "room.joined", actor_id=context.user.id, target=room_id, ip=context.session.last_ip)
    return _room_out(db, room)


@router.post("/{room_id}/leave", dependencies=[Depends(require_csrf)])
def leave_room(room_id: str, context: AuthContext = Depends(get_current_context),
               db: Session = Depends(get_db)):
    room = db.get(Room, room_id)
    if not room:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Room not found")
    if room.owner_id == context.user.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Owners must delete the room instead of leaving")
    membership = _membership(db, room_id, context.user.id)
    if membership:
        db.delete(membership)
        record(db, "room.left", actor_id=context.user.id, target=room_id, ip=context.session.last_ip)
    return {"status": "left", "room_id": room_id}


@router.put("/{room_id}/code", response_model=RoomOut, dependencies=[Depends(require_csrf)])
def update_code(room_id: str, payload: RoomCodeUpdate, request: Request,
                context: AuthContext = Depends(get_current_context),
                db: Session = Depends(get_db)):
    room = db.get(Room, room_id)
    if not room:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Room not found")
    if not _membership(db, room_id, context.user.id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not a member of this room")

    size = len(payload.code.encode("utf-8"))
    if size > request.app.state.settings.max_code_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Code is too large")

    room.code = payload.code
    if payload.language:
        room.language = payload.language
    room.updated_at = utcnow()
    record(db, "room.code_updated", actor_id=context.user.id, target=room_id,
           ip=context.session.last_ip, detail={"bytes": size})
    return _room_out(db, room)


@router.get("/{room_id}/members")
def list_members(room_id: str, context: AuthContext = Depends(get_current_context),
                 db: Session = Depends(get_db)):
    if not _membership(db, room_id, context.user.id) and context.user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not a member of this room")
    rows = db.execute(
        select(RoomMember, User).join(User, User.id == RoomMember.user_id).where(
            RoomMember.room_id == room_id
        )
    ).all()
    return {
        "members": [
            {"id": user.id, "name": user.name, "role": membership.role,
             "joined_at": membership.joined_at.isoformat()}
            for membership, user in rows
        ]
    }


@router.delete("/{room_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require_csrf)])
def delete_room(room_id: str, context: AuthContext = Depends(get_current_context),
                db: Session = Depends(get_db)):
    room = db.get(Room, room_id)
    if not room:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Room not found")
    if room.owner_id != context.user.id and context.user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the owner can delete this room")
    db.delete(room)
    record(db, "room.deleted", actor_id=context.user.id, target=room_id, ip=context.session.last_ip)
    return None
