import { clear, el } from "./dom.js";

const SVG_NS = "http://www.w3.org/2000/svg";
const COLORS = { critical: "#f43f5e", high: "#fb923c", medium: "#fbbf24", low: "#34d399" };

function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined) continue;
    node.setAttribute(key, String(value));
  }
  for (const child of children.flat()) if (child) node.append(child);
  return node;
}

export function donut(container, distribution) {
  clear(container);
  const entries = Object.entries(distribution);
  const total = entries.reduce((sum, [, value]) => sum + value, 0);
  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const root = svg("svg", { viewBox: "0 0 200 200", class: "chart", role: "img",
    "aria-label": `Risk distribution, ${total} sessions` });
  root.append(svg("circle", {
    cx: 100, cy: 100, r: radius, fill: "none", stroke: "#1f2b45", "stroke-width": 18,
  }));
  let offset = 0;
  for (const [key, value] of entries) {
    if (!value) continue;
    const length = (value / total) * circumference;
    root.append(svg("circle", {
      cx: 100, cy: 100, r: radius, fill: "none", stroke: COLORS[key] || "#64748b",
      "stroke-width": 18, "stroke-dasharray": `${length} ${circumference - length}`,
      "stroke-dashoffset": -offset, transform: "rotate(-90 100 100)", "stroke-linecap": "butt",
    }));
    offset += length;
  }
  root.append(svg("text", {
    x: 100, y: 96, "text-anchor": "middle", fill: "#e6ecf7", "font-size": 30, "font-weight": 700,
  }, document.createTextNode(String(total))));
  root.append(svg("text", {
    x: 100, y: 120, "text-anchor": "middle", fill: "#93a4c3", "font-size": 12,
  }, document.createTextNode("sessions")));
  container.append(root);

  const legend = el("div", { class: "chart-legend" },
    entries.map(([key, value]) =>
      el("span", {},
        el("span", { class: `legend-swatch swatch-${key}` }),
        `${key} · ${value}`)));
  container.append(legend);
}

export function lineChart(container, points) {
  clear(container);
  const width = 600;
  const height = 200;
  const padX = 36;
  const padY = 22;
  const max = Math.max(1, ...points.map((point) => Math.max(point.scans, point.alerts)));
  const stepX = points.length > 1 ? (width - padX * 2) / (points.length - 1) : 0;
  const y = (value) => height - padY - (value / max) * (height - padY * 2);
  const x = (index) => padX + index * stepX;

  const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, class: "chart", role: "img",
    "aria-label": "Scans and alerts over the last 12 hours" });

  for (let line = 0; line <= 4; line += 1) {
    const value = (max / 4) * line;
    root.append(svg("line", {
      x1: padX, x2: width - padX, y1: y(value), y2: y(value),
      stroke: "#1f2b45", "stroke-width": 1,
    }));
    root.append(svg("text", {
      x: padX - 8, y: y(value) + 4, "text-anchor": "end", fill: "#6b7c9e", "font-size": 10,
    }, document.createTextNode(String(Math.round(value)))));
  }

  const buildPath = (key) =>
    points.map((point, index) => `${index === 0 ? "M" : "L"}${x(index)},${y(point[key])}`).join(" ");

  root.append(svg("path", {
    d: `${buildPath("scans")} L${x(points.length - 1)},${height - padY} L${x(0)},${height - padY} Z`,
    fill: "rgba(34, 211, 238, 0.12)", stroke: "none",
  }));
  root.append(svg("path", { d: buildPath("scans"), fill: "none", stroke: "#22d3ee", "stroke-width": 2.5 }));
  root.append(svg("path", { d: buildPath("alerts"), fill: "none", stroke: "#f43f5e", "stroke-width": 2, "stroke-dasharray": "5 4" }));

  for (const [index, point] of points.entries()) {
    if (index % 3 === 0) {
      root.append(svg("text", {
        x: x(index), y: height - 4, "text-anchor": "middle", fill: "#6b7c9e", "font-size": 10,
      }, document.createTextNode(new Date(point.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }))));
    }
  }

  container.append(root);
  container.append(el("div", { class: "chart-legend" },
    el("span", {}, el("span", { class: "legend-swatch swatch-scans" }), "scans"),
    el("span", {}, el("span", { class: "legend-swatch swatch-alerts" }), "alerts")));
}
