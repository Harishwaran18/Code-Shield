"""Unit tests for the ML anomaly detector and risk scoring."""

from server.security.anomaly import SessionAnomalyDetector
from server.security.risk import combine_session_risk, scan_risk_score, session_rule_score

NORMAL = {
    "requests_per_minute": 15, "distinct_paths": 9, "failed_logins": 0,
    "scans_last_hour": 2, "payload_kb": 1, "hour_sin": 0.5, "hour_cos": 0.8,
    "ua_changed": 0, "ip_changed": 0, "admin_actions": 0,
}
SUSPICIOUS = {
    "requests_per_minute": 600, "distinct_paths": 80, "failed_logins": 6,
    "scans_last_hour": 40, "payload_kb": 300, "hour_sin": -0.9, "hour_cos": -0.4,
    "ua_changed": 1, "ip_changed": 1, "admin_actions": 25,
}


def test_detector_trains_and_persists(tmp_path):
    detector = SessionAnomalyDetector(str(tmp_path))
    detector.load_or_train()
    assert detector.trained is True
    assert (tmp_path / "anomaly.joblib").exists()
    assert detector.describe()["engine"] == "isolation_forest"


def test_normal_session_scores_low(tmp_path):
    detector = SessionAnomalyDetector(str(tmp_path))
    detector.load_or_train()
    assert detector.score(NORMAL)["score"] < 25


def test_suspicious_session_scores_high(tmp_path):
    detector = SessionAnomalyDetector(str(tmp_path))
    detector.load_or_train()
    result = detector.score(SUSPICIOUS)
    assert result["score"] > 70
    assert result["drivers"]


def test_reloaded_model_matches(tmp_path):
    first = SessionAnomalyDetector(str(tmp_path))
    first.load_or_train()
    second = SessionAnomalyDetector(str(tmp_path))
    second.load_or_train()
    assert abs(first.score(SUSPICIOUS)["score"] - second.score(SUSPICIOUS)["score"]) < 0.01


def test_heuristic_fallback_is_bounded(tmp_path):
    detector = SessionAnomalyDetector(str(tmp_path))
    score = detector._heuristic(__import__("numpy").array(list(SUSPICIOUS.values())))
    assert 0 <= score <= 100


def test_scan_risk_score_caps_at_100():
    findings = [{"severity": "critical"}] * 5
    assert scan_risk_score(findings) == 100
    assert scan_risk_score([{"severity": "low"}]) == 3


def test_session_rule_score_flags_changes():
    assert session_rule_score({"ip_changed": 1, "ua_changed": 1}) == 40
    assert session_rule_score({"failed_logins": 10}) == 30
    assert combine_session_risk(50, 20) == 60
    assert combine_session_risk(90, 100) == 100
