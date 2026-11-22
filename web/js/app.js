import { api, ensureCsrf } from "./api.js";
import { avatar, clear, el, icon, toast } from "./dom.js";
import { renderDashboard } from "./dashboard.js";
import { renderEditor } from "./editor.js";

export const state = { user: null, config: null };

const view = document.getElementById("view");
const nav = document.getElementById("nav");

export function navigate(path, replace = false) {
  if (replace) history.replaceState({}, "", path);
  else if (location.pathname !== path) history.pushState({}, "", path);
  return render();
}

export async function refreshUser() {
  try {
    const data = await api("/api/auth/me");
    state.user = data.user;
  } catch {
    state.user = null;
  }
  return state.user;
}

export async function logout() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch {
    /* the session may already be gone */
  }
  state.user = null;
  toast("Signed out", "success");
  await navigate("/login");
}

function renderNav(path) {
  clear(nav);
  const link = (href, label, active) =>
    el("a", { href, class: `nav-link${active ? " active" : ""}`, "data-link": true }, label);

  nav.append(link("/", "Home", path === "/"));
  if (state.user) {
    nav.append(link("/app", "Workspace", path === "/app"));
    if (state.user.role === "admin") nav.append(link("/dashboard", "Dashboard", path === "/dashboard"));
    nav.append(
      el("span", { class: "nav-user" },
        avatar(state.user.name),
        el("span", { class: "nav-user-name" }, state.user.name),
        el("span", { class: `badge badge-role` }, state.user.role)),
      el("button", { class: "nav-button", type: "button", onclick: logout }, "Sign out"),
    );
  } else {
    nav.append(
      el("a", { href: "/login", class: `nav-link${path === "/login" ? " active" : ""}`, "data-link": true }, "Sign in"),
      el("a", { href: "/register", class: "btn btn-primary btn-sm", "data-link": true }, "Create account"),
    );
  }
}

function renderLanding() {
  const previewLines = [
    ["import os", ""],
    ["password = \"••••••••\"", "flag"],
    ["os.system(\"ping \" + host)", "flag"],
    ["eval(user_input)", "flag"],
  ];
  return el("div", {},
    el("section", { class: "hero" },
      el("div", {},
        el("span", { class: "eyebrow" }, "Secure collaborative coding"),
        el("h1", { class: "hero-title" }, "Ship fast.", el("br"), "Stay ", el("span", { class: "accent" }, "secure.")),
        el("p", { class: "hero-sub" },
          "Code-Shield is a real-time hackathon workspace that pairs collaborative editing with ",
          "AI-driven vulnerability scanning and ML session monitoring, so teams move quickly without leaking secrets."),
        el("div", { class: "hero-actions" },
          el("a", { href: state.user ? "/app" : "/register", class: "btn btn-primary", "data-link": true },
            state.user ? "Open workspace" : "Start a room"),
          el("a", { href: "/login", class: "btn btn-ghost", "data-link": true }, "Sign in")),
        el("div", { class: "hero-points" },
          el("div", {}, el("strong", {}, "Bandit + AST"), "multi-engine analysis"),
          el("div", {}, el("strong", {}, "Isolation Forest"), "session anomaly detection"),
          el("div", {}, el("strong", {}, "Zero trust"), "hardened sessions"))),
      el("div", { class: "hero-visual" },
        el("div", { class: "card scan-preview" },
          el("div", { class: "scan-preview-head" },
            el("span", { class: "dots" },
              el("span", { class: "dot red" }), el("span", { class: "dot amber" }), el("span", { class: "dot green" })),
            el("span", {}, "live scan · main.py")),
          el("div", { class: "code-lines" },
            previewLines.map(([text, cls], index) =>
              el("div", { class: `code-line ${cls}` },
                el("span", { class: "ln" }, index + 1),
                el("span", {}, text)))),
          el("div", { class: "preview-foot" },
            el("span", { class: "badge badge-critical" }, "critical"),
            el("span", { class: "badge badge-high" }, "command injection"),
            el("span", { class: "badge badge-medium" }, "CWE-798"))))),
    el("section", { class: "feature-grid" },
      feature("shield", "AI vulnerability scanning",
        "Bandit, AST rules and secret detection run on every snippet with CWE references and fixes."),
      feature("cpu", "ML session monitoring",
        "An Isolation Forest scores each session in real time and raises alerts on suspicious behaviour."),
      feature("bolt", "Real-time collaboration",
        "WebSocket rooms sync code, cursors and chat instantly for the whole team."),
      feature("lock", "Hardened authentication",
        "bcrypt password hashing, short-lived JWTs, rotating refresh tokens and CSRF protection."),
      feature("chart", "Live security dashboard",
        "Risk distribution, active sessions, findings and alerts stream to admins every two seconds."),
      feature("scroll", "Audit trail",
        "Every login, scan and administrative action is recorded with request correlation IDs.")));
}

function feature(iconName, title, body) {
  return el("article", { class: "card feature-card" },
    el("div", { class: "feature-icon", "aria-hidden": "true" }, icon(iconName, 22)),
    el("h3", {}, title),
    el("p", {}, body));
}

function authForm({ title, subtitle, fields, submitLabel, onSubmit, alt }) {
  const errorBox = el("div", { class: "form-error", role: "alert" });
  const button = el("button", { class: "btn btn-primary btn-block", type: "submit" }, submitLabel);
  const form = el("form", { novalidate: true },
    errorBox,
    fields.map((field) => el("div", { class: "field" },
      el("label", { class: "label", for: field.name }, field.label),
      el("input", {
        class: "input", id: field.name, name: field.name, type: field.type || "text",
        autocomplete: field.autocomplete, required: true, placeholder: field.placeholder || "",
      }),
      field.hint ? el("span", { class: "input-hint" }, field.hint) : null)),
    button);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorBox.className = "form-error";
    button.disabled = true;
    const values = Object.fromEntries(new FormData(form).entries());
    try {
      await onSubmit(values);
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.className = "form-error visible";
    } finally {
      button.disabled = false;
    }
  });

  return el("div", { class: "auth-wrap" },
    el("div", { class: "card auth-card" },
      el("h1", {}, title),
      el("p", { class: "auth-sub" }, subtitle),
      form,
      el("p", { class: "auth-alt" }, alt)));
}

function renderLogin() {
  return authForm({
    title: "Welcome back",
    subtitle: "Sign in to your secure workspace.",
    fields: [
      { name: "email", label: "Email", type: "email", autocomplete: "email" },
      { name: "password", label: "Password", type: "password", autocomplete: "current-password" },
    ],
    submitLabel: "Sign in",
    onSubmit: async ({ email, password }) => {
      await api("/api/auth/login", { method: "POST", body: { email, password } });
      await refreshUser();
      toast("Signed in", "success");
      await navigate("/app");
    },
    alt: el("span", {}, "New here? ",
      el("a", { href: "/register", "data-link": true }, "Create an account")),
  });
}

function renderRegister() {
  return authForm({
    title: "Create your account",
    subtitle: "The first account becomes the workspace administrator.",
    fields: [
      { name: "name", label: "Full name", autocomplete: "name" },
      { name: "email", label: "Email", type: "email", autocomplete: "email" },
      { name: "password", label: "Password", type: "password", autocomplete: "new-password",
        hint: "At least 12 characters with upper case, lower case, a number and a symbol." },
      { name: "confirm", label: "Confirm password", type: "password", autocomplete: "new-password" },
    ],
    submitLabel: "Create account",
    onSubmit: async ({ name, email, password, confirm }) => {
      if (password !== confirm) throw new Error("Passwords do not match");
      await api("/api/auth/register", { method: "POST", body: { name, email, password } });
      await refreshUser();
      toast("Account created", "success");
      await navigate("/app");
    },
    alt: el("span", {}, "Already registered? ",
      el("a", { href: "/login", "data-link": true }, "Sign in")),
  });
}

const routes = {
  "/": { view: renderLanding, title: "Home" },
  "/login": { view: renderLogin, guest: true, title: "Sign in" },
  "/register": { view: renderRegister, guest: true, title: "Create account" },
  "/app": { view: renderEditor, auth: true, title: "Workspace" },
  "/dashboard": { view: renderDashboard, auth: true, admin: true, title: "Security dashboard" },
};

let activeCleanup = null;

async function render() {
  const path = (location.pathname.replace(/\/+$/, "") || "/");
  const route = routes[path] || routes["/"];

  if (route.auth && !state.user) return navigate("/login", true);
  if (route.guest && state.user) return navigate("/app", true);
  if (route.admin && state.user?.role !== "admin") return navigate("/app", true);

  if (activeCleanup) {
    try {
      await activeCleanup();
    } catch {
      /* a view may already be torn down */
    }
    activeCleanup = null;
  }

  clear(view);
  renderNav(path);
  document.title = `${route.title} · Code-Shield`;
  const node = await route.view();
  if (node && node.__cleanup) activeCleanup = node.__cleanup;
  view.append(node);
  view.focus({ preventScroll: true });
}

async function boot() {
  document.addEventListener("click", (event) => {
    const anchor = event.target.closest("a[data-link]");
    if (!anchor) return;
    if (anchor.origin !== location.origin) return;
    event.preventDefault();
    navigate(anchor.pathname);
  });
  window.addEventListener("popstate", () => render());

  try {
    state.config = await api("/api/config");
    document.getElementById("version").textContent = `v${state.config.version}`;
  } catch {
    state.config = null;
  }
  try {
    await ensureCsrf();
  } catch {
    // Render anyway; the next mutation retries the token.
  }
  await refreshUser();
  await render();
}

boot();
