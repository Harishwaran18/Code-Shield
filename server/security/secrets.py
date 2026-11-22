"""Data-leak prevention: detection and redaction of embedded credentials."""

import math
import re
from collections import Counter

_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical", "CWE-798",
     "Move the key to an environment variable or a managed secret store and rotate it."),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
     "critical", "CWE-321", "Remove the key from source control, rotate it and store it in a secret manager."),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical", "CWE-798",
     "Revoke the token, then read it from an environment variable."),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high", "CWE-798",
     "Revoke the token and load it from configuration at runtime."),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high", "CWE-798",
     "Restrict the key in Google Cloud and move it out of source control."),
    ("Stripe Secret Key", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"), "critical", "CWE-798",
     "Roll the key in the Stripe dashboard and use an environment variable."),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "high", "CWE-798", "Tokens in source code cannot be revoked safely; load them at runtime."),
    ("Database URI with Credentials",
     re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s'\"]+:[^\s'\"]+@"),
     "critical", "CWE-798", "Use a secret manager and a connection string without inline credentials."),
    ("Bearer Token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}"), "medium", "CWE-798",
     "Load bearer tokens from the environment instead of hardcoding them."),
    ("Hardcoded Credential",
     re.compile(r"""(?i)\b[a-z0-9_]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)\s*=\s*['"][^'"\s]{4,}['"]"""),
     "high", "CWE-798", "Read the credential from an environment variable or secret manager."),
]

_QUOTED = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{20,64})['"]""")
_URLISH = re.compile(r"^(?:https?|wss?)://")


def mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return value[:2] + "*" * max(len(value) - 2, 0)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact(text: str) -> str:
    if not text:
        return text
    for _, pattern, _, _, _ in PATTERNS:
        text = pattern.sub(lambda match: mask(match.group(0)), text)
    return text


_QUOTED_ANY = re.compile(r"""(['"])([^'"]{3,})\1""")


def redact_literals(text: str) -> str:
    """Mask quoted literals, used for messages that quote user code."""
    if not text:
        return text
    return _QUOTED_ANY.sub(lambda match: f"{match.group(1)}{mask(match.group(2))}{match.group(1)}", text)


def scan_secrets(code: str, max_findings: int = 100) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple[int, str]] = set()

    for line_number, line in enumerate(code.splitlines(), 1):
        for name, pattern, severity, cwe, remediation in PATTERNS:
            match = pattern.search(line)
            if not match or (line_number, name) in seen:
                continue
            seen.add((line_number, name))
            label = "credential" if name == "Hardcoded Credential" else name
            article = "An" if label[0].upper() in "AEIOU" else "A"
            findings.append({
                "title": f"Sensitive data: {name}",
                "category": "secret",
                "severity": severity,
                "confidence": "high",
                "line": line_number,
                "column": match.start() + 1,
                "description": f"{article} {label} appears to be hardcoded in the source.",
                "remediation": remediation,
                "cwe": cwe,
                "source": "dlp",
                "evidence": mask(match.group(0)),
            })

        for match in _QUOTED.finditer(line):
            candidate = match.group(1)
            if _URLISH.search(candidate) or candidate.isalpha():
                continue
            if _entropy(candidate) < 4.2:
                continue
            key = (line_number, "entropy")
            if key in seen:
                break
            seen.add(key)
            findings.append({
                "title": "High-entropy string (possible secret)",
                "category": "secret",
                "severity": "medium",
                "confidence": "medium",
                "line": line_number,
                "column": match.start() + 1,
                "description": "A long random-looking string may be an embedded secret or key.",
                "remediation": "Confirm the value is not a credential; if it is, move it to configuration.",
                "cwe": "CWE-798",
                "source": "entropy",
                "evidence": mask(candidate),
            })

        if len(findings) >= max_findings:
            break

    return findings[:max_findings]


def highest_severity(findings: list[dict]) -> str:
    highest = "none"
    for finding in findings:
        severity = str(finding.get("severity", "none")).lower()
        if _SEVERITY.get(severity, 0) > _SEVERITY.get(highest, 0):
            highest = severity
    return highest
