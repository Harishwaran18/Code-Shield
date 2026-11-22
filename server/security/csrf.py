"""Double-submit cookie CSRF protection."""

import secrets
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status

from server.security.passwords import constant_time_equals

CSRF_COOKIE = "cs_csrf"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def require_csrf(request: Request) -> None:
    """Dependency that rejects state-changing requests without a matching CSRF token."""
    if request.method in SAFE_METHODS:
        return

    verify_origin(request, request.app.state.settings.origins)

    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get(CSRF_HEADER)
    if not cookie or not header or not constant_time_equals(cookie, header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid",
        )


def verify_origin(request: Request, allowed_origins: list[str]) -> None:
    """Reject cross-origin state changes when the browser sends an Origin header."""
    if request.method in SAFE_METHODS:
        return
    origin = request.headers.get("origin")
    if not origin:
        return
    if origin in allowed_origins:
        return
    # Same-origin requests behind a proxy still carry the public host in Origin.
    if urlparse(origin).netloc and urlparse(origin).netloc == request.headers.get("host", ""):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Origin is not allowed",
    )
