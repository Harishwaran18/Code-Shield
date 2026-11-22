"""Dashboard metrics, alert acknowledgement and session administration tests."""


def _headers(client):
    return {"X-CSRF-Token": client.cookies.get("cs_csrf")}


def test_dashboard_payload(admin_client):
    response = admin_client.get("/api/dashboard")
    assert response.status_code == 200
    payload = response.json()
    assert set(payload["stats"]) >= {"active_sessions", "scans_24h", "avg_risk", "alerts_open"}
    assert len(payload["activity"]) == 12
    assert set(payload["risk_distribution"]) == {"low", "medium", "high", "critical"}
    assert payload["anomaly_engine"] in {"isolation_forest", "heuristic"}
    assert any(session["current"] for session in payload["sessions"])


def test_member_dashboard_is_scoped(member_client):
    payload = member_client.get("/api/dashboard").json()
    assert all(session["user_name"] == "Member User" for session in payload["sessions"])


def test_critical_scan_raises_alert_and_can_be_acknowledged(admin_client):
    headers = _headers(admin_client)
    admin_client.post("/api/scans",
                      json={"code": 'key = "AKIAZZZZZZZZZZZZZZZZ"\n', "language": "python"},
                      headers=headers)
    alerts = admin_client.get("/api/alerts").json()
    assert alerts, "expected a critical alert"
    alert = next(item for item in alerts if not item["acknowledged"])
    assert admin_client.post(f"/api/alerts/{alert['id']}/ack", headers=headers).status_code == 200
    assert admin_client.get("/api/alerts").json()[0]["acknowledged"] is True


def test_admin_can_verify_and_terminate_sessions(admin_client, member_client):
    current_id = member_client.get("/api/auth/me").json()["session"]["id"]
    sessions = admin_client.get("/api/dashboard").json()["sessions"]
    target = next(session for session in sessions if session["id"] == current_id)

    assert admin_client.post(f"/api/sessions/{target['id']}/verify",
                             headers=_headers(admin_client)).status_code == 200
    verified = admin_client.get("/api/dashboard").json()["sessions"]
    assert next(s for s in verified if s["id"] == target["id"])["verified"] is True

    assert admin_client.post(f"/api/sessions/{target['id']}/terminate",
                             headers=_headers(admin_client)).status_code == 200
    assert member_client.get("/api/auth/me").status_code == 401


def test_unknown_session_returns_404(admin_client):
    response = admin_client.post("/api/sessions/sess_missing/verify",
                                 headers=_headers(admin_client))
    assert response.status_code == 404


def test_audit_trail_records_events(admin_client):
    events = admin_client.get("/api/audit?limit=20").json()["events"]
    actions = {event["action"] for event in events}
    assert {"auth.login", "auth.register", "admin.seeded"} & actions
    assert all("created_at" in event for event in events)
