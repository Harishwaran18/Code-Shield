# Code-Shield (SecureHack AI)

A secure, AI-powered collaborative coding platform with real-time code sharing,
vulnerability scanning, data-leak prevention and ML-based user activity monitoring.

## Features

- **Collaborative editor** with WebSocket sync of edits, cursors, chat and typing indicators.
- **Vulnerability scanner** that runs [Bandit](https://bandit.readthedocs.io/) on submitted code
  and falls back to built-in pattern matching when Bandit is unavailable.
- **Data-leak prevention (DLP)** that detects hardcoded credentials, API keys, tokens,
  private keys and database URIs before code leaves the editor.
- **Security dashboard** with live session tracking, per-session risk scores,
  alerts and one-click verify / terminate actions.
- **ML anomaly detection** (`ml_detection.py`) using Isolation Forest over behavioural
  features such as typing speed, session length and command frequency.
- **Audit log** of every scan written to `audit.log`.

## Project structure

| File | Purpose |
| --- | --- |
| `app.py` | Main FastAPI application: pages, scan API, collaboration and dashboard endpoints. |
| `dlp.py` | Data-leak prevention, rate limiting and audit logging. |
| `ml_detection.py` | Isolation-forest anomaly detector and session monitor. |
| `login.html` | Login page served at `/login`. |
| `editor.html` | Collaborative editor served at `/editor`. |
| `dashboard.html` | Security dashboard served at `/dashboard`. |
| `newcode.py`, `securehack_complete.py`, `securehack_ml_integrated.py` | Standalone variants / earlier iterations of the platform. |
| `test.py`, `test_model.py`, `test_scan.py`, `debug.py` | Helper and diagnostic scripts. |

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:8000>.

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/` | Landing page |
| GET | `/login` | Login page (demo: any non-empty username) |
| GET | `/editor` | Collaborative editor |
| GET | `/dashboard` | Security dashboard |
| POST | `/api/login` | Demo login, returns a session id |
| POST | `/scan` | Scan code for vulnerabilities and secrets |
| GET | `/api/dashboard` | Dashboard snapshot (stats, sessions, alerts) |
| GET | `/api/sessions` | Active sessions |
| POST | `/api/sessions/{id}/verify` | Mark a session as verified |
| POST | `/api/sessions/{id}/terminate` | Disconnect a session |
| GET | `/investigate/{id}` | Per-session investigation page |
| WS | `/ws` | Real-time collaboration channel |
| WS | `/ws/dashboard` | Live dashboard feed (2s interval) |
| GET | `/health` | Health check |
| GET | `/debug` | Environment and file diagnostics |

## How scanning works

`POST /scan` accepts `{"code": "...", "user": "..."}` and returns:

```json
{
  "result": "Found 4 potential security issues",
  "severity": "critical",
  "vulnerabilities": [
    {"title": "...", "description": "...", "severity": "high", "line": 12}
  ],
  "secrets_found": 1
}
```

Bandit findings and DLP secret findings are merged, the highest severity is reported,
and the scan is recorded in `audit.log`. If Bandit is not installed the built-in
pattern matcher is used so the demo still works.

## Notes

- Demo accounts and sample vulnerable code are intentional teaching material, not real credentials.
- Compiled `.pyc` files, `temp/`, `secret.txt`, `audit.log` and model binaries are ignored by git.
