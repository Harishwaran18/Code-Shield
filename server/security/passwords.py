"""Password policy and hashing."""

import base64
import hashlib
import hmac
import re

import bcrypt

MIN_LENGTH = 12
MAX_LENGTH = 128
BCRYPT_ROUNDS = 12

_CLASSES = (
    re.compile(r"[a-z]"),
    re.compile(r"[A-Z]"),
    re.compile(r"[0-9]"),
    re.compile(r"[^A-Za-z0-9]"),
)


def validate_password_strength(password: str) -> None:
    if len(password) < MIN_LENGTH:
        raise ValueError(f"Password must be at least {MIN_LENGTH} characters long")
    if len(password) > MAX_LENGTH:
        raise ValueError(f"Password must be at most {MAX_LENGTH} characters long")
    if sum(bool(pattern.search(password)) for pattern in _CLASSES) < 3:
        raise ValueError(
            "Password must contain at least three of: lowercase, uppercase, digit, symbol"
        )
    if password.lower() in {"password1234", "1234567890ab", "qwertyuiop12"}:
        raise ValueError("Password is too common")


def _prehash(password: str) -> bytes:
    # bcrypt silently truncates beyond 72 bytes; pre-hash so long passwords stay distinct.
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode())
    except (ValueError, TypeError):
        return False


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())
