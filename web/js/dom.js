export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else node.setAttribute(key, value === true ? "" : String(value));
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function initials(name) {
  return (name || "?")
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part[0])
    .slice(0, 2)
    .join("")
    .toUpperCase() || "?";
}

export function fmtDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export function timeAgo(value) {
  if (!value) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

let toastTimer = null;
export function toast(message, kind = "") {
  const node = document.getElementById("toast");
  if (!node) return;
  node.textContent = message;
  node.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.className = "toast";
  }, 4200);
}

export function badge(severity, label) {
  const value = (severity || "none").toLowerCase();
  return el("span", { class: `badge badge-${value}` }, label || value);
}

export function avatar(name) {
  return el("span", { class: "avatar", title: name || "User", "aria-hidden": "true" }, initials(name));
}

export function emptyState(message) {
  return el("div", { class: "empty" }, message);
}

const ICONS = {
  shield: ["M12 2 20 6v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z", "m8.6 12 2.4 2.4 4.4-4.8"],
  cpu: ["M7 7h10v10H7z", "M4 10h3M4 14h3M17 10h3M17 14h3M10 4v3M14 4v3M10 17v3M14 17v3"],
  bolt: ["M13 2 4 14h6l-1 8 9-12h-6z"],
  lock: ["M6 10h12v10H6z", "M9 10V7a3 3 0 0 1 6 0v3"],
  chart: ["M4 20V10M10 20V4M16 20v-7M22 20H2"],
  scroll: ["M6 3h12v18H6z", "M9 8h6M9 12h6M9 16h4"],
  alert: ["M12 3 2.5 20h19z", "M12 9v5M12 17h.01"],
};

export function icon(name, size = 20) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  for (const path of ICONS[name] || ICONS.shield) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", "path");
    node.setAttribute("d", path);
    svg.append(node);
  }
  return svg;
}
