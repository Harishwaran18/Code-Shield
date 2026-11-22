"""Risk scoring shared by the scanner and the session monitor."""

SEVERITY_WEIGHTS = {"critical": 45, "high": 22, "medium": 8, "low": 3, "none": 0}


def scan_risk_score(findings: list[dict]) -> int:
    score = 0
    for finding in findings:
        score += SEVERITY_WEIGHTS.get(str(finding.get("severity", "none")).lower(), 0)
    return min(100, score)


def session_rule_score(features: dict) -> float:
    score = 0.0
    score += 25.0 if features.get("ip_changed") else 0.0
    score += 15.0 if features.get("ua_changed") else 0.0
    score += min(30.0, 10.0 * float(features.get("failed_logins", 0)))
    if float(features.get("requests_per_minute", 0)) > 120:
        score += 20.0
    if float(features.get("payload_kb", 0)) > 100:
        score += 15.0
    if float(features.get("admin_actions", 0)) > 10:
        score += 10.0
    return min(100.0, score)


def combine_session_risk(anomaly_score: float, rule_score: float) -> float:
    return round(min(100.0, anomaly_score + 0.5 * rule_score), 1)


def severity_label(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
