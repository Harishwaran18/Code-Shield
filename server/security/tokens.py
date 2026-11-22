"""JWT issuance and validation with revocation support."""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt

from server.utils import utcnow

ALGORITHM = "HS256"
ACCESS = "access"
REFRESH = "refresh"


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired or revoked."""


@dataclass(frozen=True)
class TokenClaims:
    sub: str
    sid: str
    role: str
    jti: str
    type: str
    exp: datetime


def _encode(secret: str, user_id: str, session_id: str, role: str, token_type: str, ttl: timedelta) -> tuple[str, str, datetime]:
    now = utcnow()
    expires_at = now + ttl
    jti = secrets.token_hex(16)
    claims = {
        "sub": user_id,
        "sid": session_id,
        "role": role,
        "jti": jti,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return jwt.encode(claims, secret, algorithm=ALGORITHM), jti, expires_at


def create_access_token(secret: str, user_id: str, session_id: str, role: str, ttl: timedelta):
    return _encode(secret, user_id, session_id, role, ACCESS, ttl)


def create_refresh_token(secret: str, user_id: str, session_id: str, role: str, ttl: timedelta):
    return _encode(secret, user_id, session_id, role, REFRESH, ttl)


def decode_token(secret: str, token: str, expected_type: str) -> TokenClaims:
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "iat", "jti", "sub", "sid", "type"]},
            leeway=10,
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("Token is invalid") from exc

    if payload.get("type") != expected_type:
        raise TokenError("Unexpected token type")

    return TokenClaims(
        sub=payload["sub"],
        sid=payload["sid"],
        role=payload.get("role", "member"),
        jti=payload["jti"],
        type=payload["type"],
        exp=datetime.fromtimestamp(payload["exp"]),
    )


def hash_jti(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()
