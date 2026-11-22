"""Data leak prevention, rate limiting and audit logging for SecureHack AI."""

import hashlib
import json
import re
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, List, Optional

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical",
     "Hardcoded AWS access key. Move it to an environment variable or secret manager."),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
     "critical", "Embedded private key. Never commit private keys to source control."),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "critical",
     "Hardcoded GitHub token. Revoke it and use environment variables."),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "high",
     "Hardcoded Slack token detected."),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "high",
     "Hardcoded Google API key detected."),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9A-Za-z]{16,}"), "critical",
     "Hardcoded Stripe secret key detected."),
    ("JSON Web Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "high", "Hardcoded JSON Web Token detected."),
    ("Hardcoded Credential", re.compile(
        r"""(?i)\b[a-z0-9_]*(?:password|passwd|pwd|secret|api[_-]?key|token)\s*=\s*['"][^'"\s]{4,}['"]"""),
     "high", "Hardcoded credential. Read it from an environment variable instead."),
    ("Database URI", re.compile(r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^\s'\"]+:[^\s'\"]+@"),
     "critical", "Connection string with embedded credentials detected."),
    ("Generic Bearer Token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}"), "medium",
     "Hardcoded bearer token detected."),
]

DEVICE_HINTS = [
    ("Mobile", re.compile(r"(?i)iphone|android|mobile")),
    ("Tablet", re.compile(r"(?i)ipad|tablet")),
    ("Desktop", re.compile(r"(?i)windows|macintosh|linux|x11")),
]


def risk_class_for_score(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def describe_device(user_agent: str) -> str:
    for label, pattern in DEVICE_HINTS:
        if pattern.search(user_agent or ""):
            return label
    return "Unknown"


class DataLeakPrevention:
    """Scans source code for credentials and sensitive data before it leaves the editor."""

    def __init__(self, max_findings: int = 50):
        self.max_findings = max_findings

    def scan_for_secrets(self, code: str) -> List[dict]:
        findings = []
        for line_number, line in enumerate(code.splitlines(), 1):
            for name, pattern, risk, description in SECRET_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                findings.append({
                    "title": f"Sensitive Data: {name}",
                    "description": description,
                    "severity": risk,
                    "risk": risk,
                    "line": line_number,
                    "match": self.mask(match.group(0)),
                })
                if len(findings) >= self.max_findings:
                    return findings
        return findings

    def redact(self, text: str) -> str:
        if not text:
            return text
        for _, pattern, _, _ in SECRET_PATTERNS:
            text = pattern.sub(lambda match: self.mask(match.group(0)), text)
        return text

    @staticmethod
    def mask(value: str) -> str:
        value = value.strip()
        if len(value) <= 8:
            return value[:2] + "*" * max(len(value) - 2, 0)
        return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


class RateLimiter:
    """Fixed-window rate limiter keyed by client identifier."""

    def __init__(self, max_requests: int = 120, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def check_rate_limit(self, client_id: str) -> bool:
        now = time.time()
        window = self._hits[client_id]
        while window and now - window[0] > self.window_seconds:
            window.popleft()
        if len(window) >= self.max_requests:
            return False
        window.append(now)
        return True


class CodeAuditLogger:
    """In-memory audit trail of scans, persisted as JSON lines when possible."""

    def __init__(self, log_path: str = "audit.log", max_events: int = 200):
        self.log_path = log_path
        self.max_events = max_events
        self._events: Deque[dict] = deque(maxlen=max_events)

    def log_scan(self, user: Optional[str], code: str, findings: List[dict]) -> dict:
        event = {
            "type": "scan",
            "user": user or "anonymous",
            "timestamp": datetime.now().isoformat(),
            "code_hash": hashlib.sha256(code.encode("utf-8")).hexdigest()[:16],
            "findings": len(findings),
            "highest_severity": self._highest_severity(findings),
        }
        self._record(event)
        return event

    def recent(self, limit: int = 20) -> List[dict]:
        return list(self._events)[-limit:][::-1]

    def stats(self) -> dict:
        events = list(self._events)
        return {
            "scans": len(events),
            "anomalies": sum(1 for e in events if e["highest_severity"] in ("high", "critical")),
        }

    def _record(self, event: dict) -> None:
        self._events.append(event)
        try:
            with open(self.log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event) + "\n")
        except OSError:
            pass

    @staticmethod
    def _highest_severity(findings: List[dict]) -> str:
        highest = "none"
        for finding in findings:
            severity = str(finding.get("severity", "none")).lower()
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest, 0):
                highest = severity
        return highest
