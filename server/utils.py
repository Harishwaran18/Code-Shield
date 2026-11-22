"""Small shared helpers."""

import re
from datetime import UTC, datetime

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def utcnow() -> datetime:
    """Naive UTC timestamp, which is how SQLite stores datetimes."""
    return datetime.now(UTC).replace(tzinfo=None)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    import uuid

    return f"{prefix}_{uuid.uuid4().hex}"


def is_sha256(value: str) -> bool:
    return bool(_SHA256_RE.match(value))


_DEVICE_HINTS = (
    ("Mobile", ("iphone", "android", "mobile")),
    ("Tablet", ("ipad", "tablet")),
    ("Desktop", ("windows", "macintosh", "linux", "x11")),
)


def device_label(user_agent: str) -> str:
    lowered = (user_agent or "").lower()
    for label, needles in _DEVICE_HINTS:
        if any(needle in lowered for needle in needles):
            return label
    return "Unknown"
