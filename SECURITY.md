# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 2.x | Yes |
| 1.x | No (prototype, kept under `legacy/` for reference only) |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories:
**Security → Advisories → Report a vulnerability** on this repository.

Include the affected endpoint or component, reproduction steps, impact, and any
suggested remediation. Do not open a public issue for an unfixed vulnerability.
We aim to acknowledge reports within 3 business days and to ship a fix or mitigation
within 30 days for high-severity issues.

## Security model

Code-Shield applies defence in depth across five layers.

### 1. Edge and transport

- All state-changing requests require a matching CSRF token (double submit) and a
  verified `Origin`. Same-origin requests are recognised through the `Host` header so
  the application works behind a reverse proxy without a static origin list.
- Cross-origin requests are rejected unless the origin appears in `CS_ALLOWED_ORIGINS`.
- WebSocket upgrades run the same origin and session checks before the handshake is
  accepted; unauthorised upgrades are closed with an HTTP 403.
- Cookies are `HttpOnly`, `SameSite=Lax`, path-scoped and `Secure` in production.

### 2. Authentication and sessions

- Passwords are hashed with bcrypt (cost 12). The policy requires 12+ characters with
  upper case, lower case, a digit and a symbol.
- Access tokens are JWTs signed with HS256 and expire after 15 minutes by default.
- Refresh tokens rotate on every use. Presenting a rotated token revokes the session
  and raises a high-severity alert.
- Five failed attempts lock the account for 15 minutes; authentication errors are
  generic and never reveal whether an account exists.
- Password changes revoke every other session for that user.

### 3. Authorisation

- Identity is resolved from the signed access token and the server-side session record
  on every request; the session's revocation state is checked each time.
- Room membership is enforced for room reads, edits, scans and WebSocket connections.
- Scans, alerts and sessions are scoped to their owner; administrators see the global
  scope through explicit role checks (`require_admin`).
- The dashboard never trusts client-supplied identifiers for scoping.

### 4. Data handling

- Secret detection runs before persistence: AWS keys, GitHub/Slack/Stripe tokens,
  private keys, JWTs, database URLs and hardcoded credential assignments.
- Matched literals are redacted from stored code and from API responses; only masked
  previews are returned.
- Validation errors return field names and messages, never the submitted values.
- Logs are structured JSON with request IDs; passwords and tokens are never logged.

### 5. Detection and response

- Every authenticated request is scored by an Isolation Forest across ten features
  (velocity, path spread, failed logins, scan volume, payload size, time of day,
  user-agent and IP changes, administrative activity). A heuristic fallback keeps the
  service working if the model cannot be loaded.
- Risk scores combine ML output with deterministic rules (IP/UA change, failed logins,
  scan bursts, administrative actions).
- Critical scan findings raise alerts; alerts can be acknowledged by operators.
- Administrative actions, authentication events, scans and session changes are written
  to an append-only audit trail with actor, target, IP and request ID.

## Threat model

| Threat | Control |
| --- | --- |
| Credential stuffing / brute force | Per-IP auth rate limit, per-account lockout, generic errors, bcrypt cost 12. |
| Session theft | Short-lived access tokens, rotating refresh tokens with reuse detection, revocation, HttpOnly/Secure cookies. |
| Cross-site request forgery | Double-submit token plus Origin verification on every mutation and WebSocket upgrade. |
| Cross-site scripting | Strict CSP (no inline script, no `unsafe-eval`), DOM built with `textContent`, no `innerHTML` for user data. |
| SQL injection | SQLAlchemy parameterised queries only. |
| IDOR / horizontal privilege escalation | Server-side ownership and membership checks on every resource. |
| Secret leakage | DLP detection and redaction before storage and in responses. |
| Malicious code execution during scanning | Bandit runs with a fixed argv, a timeout, no shell and no evaluation of the analysed code. |
| Denial of service | Rate limits, payload ceilings, scan timeouts, bounded history queries. |
| Insider misuse | Role separation, audit trail, session verification and termination. |
| Anomalous sessions | ML scoring, deterministic rules, alerts and admin review. |

## Deployment hardening checklist

- [ ] Set a unique, random `CS_SECRET_KEY` (32+ bytes) and store it in a secret manager.
- [ ] Set `CS_ENVIRONMENT=production` so cookies are `Secure`.
- [ ] Terminate TLS in front of the application and forward `X-Forwarded-Proto`.
- [ ] Set `CS_ALLOWED_ORIGINS` to your public origin(s) and nothing else.
- [ ] Change the seeded administrator password immediately after first boot.
- [ ] Run behind a reverse proxy that enforces request size limits and timeouts.
- [ ] Keep `data/` on a dedicated volume with restrictive permissions and back it up.
- [ ] Export audit logs to a central, append-only store.
- [ ] Monitor `/api/health`, alert volume and lockout events.
- [ ] Pin dependency versions and run `pip-audit` or Dependabot in CI.
- [ ] For multi-instance deployments, replace SQLite with PostgreSQL and move rate
      limiting and the WebSocket hub to a shared store (Redis).

## Known limitations

- SQLite is the default store; it is suitable for single-node deployments and demos,
  not for horizontally scaled production clusters.
- Rate limiting and the WebSocket hub are in-process. Multiple workers or replicas
  require a shared backend.
- Bandit is a static analyser; it does not execute or prove the absence of
  vulnerabilities. Treat findings as signals, not guarantees.
- The first registered account becomes an administrator when no administrator is
  seeded. Always seed `CS_ADMIN_EMAIL` / `CS_ADMIN_PASSWORD` before exposing the
  service.
- Anomaly scores are calibrated on a synthetic baseline. Retrain on real traffic
  before relying on them for enforcement.

## Secure development

Every change is expected to pass:

```bash
ruff check server tests app.py
bandit -r server -ll
pytest
```

CI enforces these gates on every push to `main` and on every pull request, together
with a syntax check of the frontend modules. New endpoints must include authorisation
checks, validation models and tests for both the allowed and the denied path.
