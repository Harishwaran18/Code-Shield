"""Vulnerability scanning tests."""

VULNERABLE_PYTHON = '''import os
password = "admin123"
aws_key = "AKIAZZZZZZZZZZZZZZZZ"
os.system("ping " + host)
eval(user_input)
query = f"SELECT * FROM users WHERE name = {name}"
'''


def test_scan_requires_authentication(client):
    assert client.post("/api/scans", json={"code": "print(1)"}).status_code == 403


def test_python_scan_detects_findings_and_redacts_secrets(admin_client):
    headers = {"X-CSRF-Token": admin_client.cookies.get("cs_csrf")}
    response = admin_client.post("/api/scans",
                                 json={"code": VULNERABLE_PYTHON, "language": "python"},
                                 headers=headers)
    assert response.status_code == 200
    scan = response.json()
    assert scan["highest_severity"] == "critical"
    assert scan["risk_score"] > 50
    assert scan["findings_count"] >= 4
    titles = " ".join(finding["title"] for finding in scan["findings"])
    assert "AWS Access Key" in titles
    assert "Use of os.system" in titles
    assert all(finding["cwe"] for finding in scan["findings"] if finding["severity"] != "low")
    body = response.text
    assert "admin123" not in body
    assert "AKIAZZZZZZZZZZZZZZZZ" not in body


def test_javascript_scan_uses_language_rules(admin_client):
    headers = {"X-CSRF-Token": admin_client.cookies.get("cs_csrf")}
    code = 'eval(input);\ndocument.getElementById("x").innerHTML = data;\n'
    response = admin_client.post("/api/scans",
                                 json={"code": code, "language": "javascript"},
                                 headers=headers)
    assert response.status_code == 200
    titles = " ".join(finding["title"] for finding in response.json()["findings"])
    assert "eval" in titles and "innerHTML" in titles


def test_clean_code_scores_zero(admin_client):
    headers = {"X-CSRF-Token": admin_client.cookies.get("cs_csrf")}
    response = admin_client.post("/api/scans",
                                 json={"code": "def add(a, b):\n    return a + b\n",
                                       "language": "python"},
                                 headers=headers)
    assert response.status_code == 200
    assert response.json()["findings_count"] == 0
    assert response.json()["risk_score"] == 0


def test_scan_size_limit(admin_client):
    headers = {"X-CSRF-Token": admin_client.cookies.get("cs_csrf")}
    response = admin_client.post("/api/scans",
                                 json={"code": "a" * 300_000, "language": "python"},
                                 headers=headers)
    assert response.status_code == 413


def test_scan_history_and_detail(admin_client):
    headers = {"X-CSRF-Token": admin_client.cookies.get("cs_csrf")}
    created = admin_client.post("/api/scans", json={"code": "print('hello')"},
                                headers=headers).json()
    listing = admin_client.get("/api/scans?limit=5").json()
    assert listing["total"] >= 1
    assert any(item["id"] == created["id"] for item in listing["items"])

    detail = admin_client.get(f"/api/scans/{created['id']}")
    assert detail.status_code == 200
    assert detail.json()["id"] == created["id"]

    assert admin_client.delete(f"/api/scans/{created['id']}",
                               headers=headers).status_code == 204
    assert admin_client.get(f"/api/scans/{created['id']}").status_code == 404


def test_scan_requires_room_membership(admin_client, member_client):
    headers = {"X-CSRF-Token": admin_client.cookies.get("cs_csrf")}
    room = admin_client.post("/api/rooms", json={"name": "Private Room"},
                             headers=headers).json()

    member_headers = {"X-CSRF-Token": member_client.cookies.get("cs_csrf")}
    response = member_client.post("/api/scans",
                                  json={"code": "print(1)", "room_id": room["id"]},
                                  headers=member_headers)
    assert response.status_code == 403


def test_member_cannot_read_other_users_scan(admin_client, member_client):
    headers = {"X-CSRF-Token": admin_client.cookies.get("cs_csrf")}
    scan = admin_client.post("/api/scans", json={"code": "print('private')"},
                             headers=headers).json()
    assert member_client.get(f"/api/scans/{scan['id']}").status_code == 404
