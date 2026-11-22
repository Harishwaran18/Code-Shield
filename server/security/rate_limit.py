"""In-process sliding-window rate limiting.

For multi-instance deployments set CS_REDIS_URL and swap the store for Redis;
the interface stays the same.
"""

import threading
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

AUTH_PATHS = {"/api/auth/login", "/api/auth/register", "/api/auth/refresh"}


class SlidingWindowLimiter:
    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            window = self._hits[key]
            while window and now - window[0] > self.window_seconds:
                window.popleft()
            if len(window) >= limit:
                retry_after = max(1, int(self.window_seconds - (now - window[0])))
                return False, retry_after
            window.append(now)
            return True, 0


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit: int, auth_limit: int, window_seconds: int = 60) -> None:
        super().__init__(app)
        self.limit = limit
        self.auth_limit = auth_limit
        self.limiter = SlidingWindowLimiter(window_seconds)

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        is_auth = request.url.path in AUTH_PATHS
        bucket = "auth" if is_auth else "api"
        allowed, retry_after = self.limiter.allow(
            f"{client_ip}:{bucket}", self.auth_limit if is_auth else self.limit
        )
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "rate_limited",
                        "message": "Too many requests. Please slow down.",
                    }
                },
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)
