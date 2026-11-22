import { api, wsUrl } from "./api.js";
import { navigate } from "./app.js";
import { badge, clear, el, emptyState, fmtDate, icon, timeAgo, toast } from "./dom.js";
import { donut, lineChart } from "./charts.js";

const riskClass = (score) =>
  score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";

function statCard(label, value, tone = "") {
  return el("div", { class: "card stat-card" },
    el("div", { class: "stat-label" }, label),
    el("div", { class: `stat-value ${tone}` }, String(value)));
}

export async function renderDashboard() {
  let data = null;
  let socket = null;
  let poll = null;
  let disposed = false;

  const statsGrid = el("div", { class: "stat-grid" });
  const activityChart = el("div", {});
  const riskChart = el("div", {});
  const sessionsBody = el("tbody");
  const alertsBox = el("div", { class: "alerts" }, emptyState("No alerts."));
  const scansBox = el("div", {});
  const auditBox = el("div", { class: "alerts" }, emptyState("Load the audit trail to inspect events."));
  const engineBadge = el("span", { class: "badge badge-role" }, "…");
  const updatedAt = el("span", { class: "muted small" }, "loading…");

  async function act(path, message) {
    try {
      await api(path, { method: "POST" });
      toast(message, "success");
      await load();
    } catch (error) {
      toast(error.message, "error");
      if (error.status === 401) navigate("/login");
    }
  }

  function renderSessions(sessions) {
    clear(sessionsBody);
    if (!sessions.length) {
      sessionsBody.append(el("tr", {}, el("td", { colspan: "6" }, emptyState("No active sessions."))));
      return;
    }
    for (const session of sessions) {
      sessionsBody.append(el("tr", {},
        el("td", {},
          el("div", { class: "table-user" }, session.user_name),
          session.current ? el("div", { class: "table-sub" }, "this session") : null),
        el("td", {}, session.ip),
        el("td", {}, session.device),
        el("td", {}, timeAgo(session.created_at)),
        el("td", {},
          el("span", { class: `badge badge-${riskClass(session.risk_score)}` },
            `${Math.round(session.risk_score)} ${riskClass(session.risk_score)}`)),
        el("td", {},
          el("div", { class: "row-actions" },
            session.verified
              ? el("span", { class: "badge badge-low" }, "verified")
              : el("button", { class: "btn btn-sm", type: "button",
                  onclick: () => act(`/api/sessions/${session.id}/verify`, "Session verified") }, "Verify"),
            el("button", { class: "btn btn-sm btn-danger", type: "button",
              onclick: () => act(`/api/sessions/${session.id}/terminate`, "Session terminated") }, "Terminate")))));
    }
  }

  function renderAlerts(alerts) {
    clear(alertsBox);
    if (!alerts.length) {
      alertsBox.append(emptyState("No alerts in the last 7 days."));
      return;
    }
    for (const alert of alerts) {
      alertsBox.append(el("div", { class: `alert-item ${alert.severity}` },
        el("span", { class: "alert-icon", "aria-hidden": "true" }, icon("alert", 16)),
        el("div", { class: "stack" },
          el("div", { class: "alert-title" }, alert.title),
          el("div", { class: "alert-body" }, alert.message),
          el("div", { class: "alert-time" }, `${fmtDate(alert.created_at)} · ${alert.severity}`),
          alert.acknowledged
            ? el("span", { class: "badge badge-low" }, "acknowledged")
            : el("button", { class: "btn btn-sm", type: "button",
                onclick: () => act(`/api/alerts/${alert.id}/ack`, "Alert acknowledged") }, "Acknowledge"))));
    }
  }

  function renderScans(scans) {
    clear(scansBox);
    if (!scans.length) {
      scansBox.append(emptyState("No scans in the last 24 hours."));
      return;
    }
    for (const scan of scans) {
      const cls = riskClass(scan.risk_score);
      scansBox.append(el("div", { class: "scan-row" },
        badge(scan.highest_severity),
        el("span", {}, `${scan.findings_count} finding${scan.findings_count === 1 ? "" : "s"}`),
        el("span", { class: "spacer" }),
        el("span", { class: "risk-meter" }, el("span", { class: `risk-${cls}` })),
        el("span", { class: "muted small" }, `${scan.risk_score}/100`),
        el("span", { class: "muted small" }, timeAgo(scan.created_at))));
    }
  }

  function render() {
    if (!data) return;
    engineBadge.textContent = `engine: ${data.anomaly_engine}`;
    updatedAt.textContent = `updated ${new Date().toLocaleTimeString()}`;

    clear(statsGrid);
    statsGrid.append(
      statCard("Active sessions", data.stats.active_sessions),
      statCard("Scans (24h)", data.stats.scans_24h),
      statCard("Findings (24h)", data.stats.findings_24h,
        data.stats.findings_24h > 0 ? "warn" : "ok"),
      statCard("Critical (24h)", data.stats.critical_findings_24h,
        data.stats.critical_findings_24h > 0 ? "danger" : "ok"),
      statCard("Average risk", data.stats.avg_risk.toFixed(1),
        data.stats.avg_risk >= 50 ? "warn" : ""),
      statCard("Open alerts", data.stats.alerts_open,
        data.stats.alerts_open > 0 ? "danger" : "ok"));

    clear(activityChart);
    lineChart(activityChart, data.activity);
    clear(riskChart);
    donut(riskChart, data.risk_distribution);

    renderSessions(data.sessions);
    renderAlerts(data.alerts);
    renderScans(data.recent_scans);
  }

  async function load() {
    try {
      data = await api("/api/dashboard");
      render();
    } catch (error) {
      if (error.status === 401) return navigate("/login");
      if (error.status === 403) return navigate("/app");
      toast(error.message, "error");
    }
  }

  async function loadAudit() {
    try {
      const result = await api("/api/audit?limit=50");
      clear(auditBox);
      if (!result.events.length) {
        auditBox.append(emptyState("No audit events yet."));
        return;
      }
      for (const event of result.events) {
        auditBox.append(el("div", { class: "alert-item low" },
          el("div", { class: "stack" },
            el("div", { class: "alert-title" }, event.action),
            el("div", { class: "alert-body" },
              `${event.actor_id || "system"} → ${event.target || "—"} · ${event.ip || "unknown IP"}`),
            el("div", { class: "alert-time" }, fmtDate(event.created_at)))));
      }
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function connect() {
    try {
      socket = new WebSocket(wsUrl("/ws/dashboard"));
    } catch {
      startPolling();
      return;
    }
    socket.onmessage = (event) => {
      try {
        data = JSON.parse(event.data);
        render();
      } catch {
        /* ignore malformed frames */
      }
    };
    socket.onopen = () => {
      clearInterval(poll);
      poll = null;
    };
    socket.onclose = () => {
      if (!disposed) startPolling();
    };
  }

  function startPolling() {
    if (poll) return;
    poll = setInterval(load, 8000);
  }

  const header = el("div", { class: "row" },
    el("div", {},
      el("h1", {}, "Security dashboard"),
      el("p", { class: "muted small" }, "Live session risk, vulnerability scans and alerts.")),
    el("span", { class: "spacer" }),
    engineBadge,
    updatedAt,
    el("button", { class: "btn btn-sm", type: "button", onclick: load }, "Refresh"));

  const layout = el("div", { class: "stack" },
    header,
    statsGrid,
    el("div", { class: "chart-grid" },
      el("div", { class: "card card-pad" },
        el("div", { class: "panel-title" }, "Activity", el("span", { class: "muted" }, "last 12 hours")),
        activityChart),
      el("div", { class: "card card-pad" },
        el("div", { class: "panel-title" }, "Risk distribution", el("span", { class: "muted" }, "active sessions")),
        riskChart)),
    el("div", { class: "card card-pad" },
      el("div", { class: "panel-title" }, "Active sessions", el("span", { class: "muted" }, "streaming every 2s")),
      el("div", { class: "table-wrap" },
        el("table", {},
          el("thead", {}, el("tr", {},
            el("th", {}, "User"), el("th", {}, "IP"), el("th", {}, "Device"),
            el("th", {}, "Started"), el("th", {}, "Risk"), el("th", {}, "Actions"))),
          sessionsBody))),
    el("div", { class: "chart-grid" },
      el("div", { class: "card card-pad" },
        el("div", { class: "panel-title" }, "Alerts", el("span", { class: "muted" }, "last 7 days")),
        alertsBox),
      el("div", { class: "card card-pad" },
        el("div", { class: "panel-title" }, "Recent scans", el("span", { class: "muted" }, "last 24 hours")),
        scansBox)),
    el("div", { class: "card card-pad" },
      el("div", { class: "panel-title" }, "Audit trail",
        el("button", { class: "btn btn-sm", type: "button", onclick: loadAudit }, "Load events")),
      auditBox));

  async function cleanup() {
    disposed = true;
    clearInterval(poll);
    poll = null;
    if (socket) {
      const ws = socket;
      socket = null;
      ws.onclose = null;
      try {
        ws.close();
      } catch {
        /* already closed */
      }
    }
  }
  layout.__cleanup = cleanup;

  await load();
  connect();
  return layout;
}
