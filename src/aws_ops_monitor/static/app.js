"use strict";

const REFRESH_MS = 30_000;
const state = { hours: 24, points: [], refreshTimer: null };

const byId = (id) => document.getElementById(id);

function pick(object, paths, fallback = null) {
  for (const path of paths) {
    const parts = path.split(".");
    let value = object;
    for (const part of parts) {
      if (value === null || value === undefined || typeof value !== "object") {
        value = undefined;
        break;
      }
      value = value[part];
    }
    if (value !== undefined && value !== null) return value;
  }
  return fallback;
}

function finiteNumber(value) {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) ? number : null;
}

function formatBytes(value) {
  const number = finiteNumber(value);
  if (number === null || number < 0) return "—";
  if (number === 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const exponent = Math.min(Math.floor(Math.log(number) / Math.log(1024)), units.length - 1);
  const scaled = number / (1024 ** exponent);
  const digits = scaled >= 100 || exponent === 0 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(digits)} ${units[exponent]}`;
}

function formatDuration(seconds) {
  const value = finiteNumber(seconds);
  if (value === null || value < 0) return "—";
  const days = Math.floor(value / 86400);
  const hours = Math.floor((value % 86400) / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function formatAge(timestamp) {
  if (timestamp === null || timestamp === undefined) return "—";
  let time;
  if (typeof timestamp === "number") {
    time = timestamp < 10_000_000_000 ? timestamp * 1000 : timestamp;
  } else {
    time = Date.parse(timestamp);
  }
  if (!Number.isFinite(time)) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

function formatClock(timestamp) {
  if (timestamp === null || timestamp === undefined) return "Waiting for collector";
  const date = new Date(typeof timestamp === "number" && timestamp < 10_000_000_000 ? timestamp * 1000 : timestamp);
  if (Number.isNaN(date.getTime())) return "Collector timestamp unavailable";
  return `Updated ${date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}`;
}

async function fetchJSON(path) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch(path, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data.message || `Monitor API returned ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return data;
  } finally {
    window.clearTimeout(timeout);
  }
}

function setStatus(rawStatus) {
  const valid = new Set([
    "healthy", "ok", "running", "degraded", "warning", "disabled",
    "critical", "failed", "error", "unavailable",
  ]);
  const status = String(rawStatus || "unknown").toLowerCase();
  const safeStatus = valid.has(status) ? status : "unknown";
  const element = byId("overall-status");
  element.className = `status-pill status-${safeStatus}`;
  element.lastElementChild.textContent = safeStatus;
}

function setNotice(message) {
  const notice = byId("notice");
  notice.textContent = message || "";
  notice.hidden = !message;
}

function setProgress(name, used, total, directPercent = null) {
  const usedNumber = finiteNumber(used);
  const totalNumber = finiteNumber(total);
  const supplied = finiteNumber(directPercent);
  let percent = supplied;
  if (percent === null && usedNumber !== null && totalNumber && totalNumber > 0) {
    percent = (usedNumber / totalNumber) * 100;
  }
  percent = percent === null ? 0 : Math.max(0, Math.min(100, percent));
  byId(`${name}-bar`).value = percent;
  byId(`${name}-bar`).textContent = `${Math.round(percent)}%`;
  if (usedNumber !== null && totalNumber !== null) {
    byId(`${name}-label`).textContent = `${formatBytes(usedNumber)} / ${formatBytes(totalNumber)}`;
  } else if (supplied !== null) {
    byId(`${name}-label`).textContent = `${Math.round(percent)}%`;
  } else {
    byId(`${name}-label`).textContent = "—";
  }
}

function renderOverview(data) {
  setNotice("");
  setStatus(pick(data, ["status", "overall_status", "health.status"], "unknown"));

  const collectedAt = pick(data, ["collected_at", "captured_at", "timestamp", "generated_at"]);
  byId("updated").textContent = formatClock(collectedAt);
  byId("collector-age").textContent = formatAge(collectedAt);

  const hostRx = pick(data, [
    "traffic.host.rx_bytes_window",
    "traffic.host.inbound_bytes",
    "traffic.host.rx_delta_bytes",
    "host.rx_delta_bytes",
    "host_rx_bytes",
    "net_rx_bytes",
  ]);
  const hostTx = pick(data, [
    "traffic.host.tx_bytes_window",
    "traffic.host.outbound_bytes",
    "traffic.host.tx_delta_bytes",
    "host.tx_delta_bytes",
    "host_tx_bytes",
    "net_tx_bytes",
  ]);
  byId("host-rx").textContent = formatBytes(hostRx);
  byId("host-tx").textContent = formatBytes(hostTx);

  const rxTotal = pick(data, ["traffic.host.rx_bytes_total", "host.rx_bytes_total", "rx_bytes_total"]);
  const txTotal = pick(data, ["traffic.host.tx_bytes_total", "host.tx_bytes_total", "tx_bytes_total"]);
  byId("host-rx-note").textContent = rxTotal === null ? "Interface delta in selected window" : `${formatBytes(rxTotal)} since interface reset`;
  byId("host-tx-note").textContent = txTotal === null ? "Interface delta in selected window" : `${formatBytes(txTotal)} since interface reset`;

  const xrayUp = finiteNumber(pick(data, [
    "traffic.xray.uplink_bytes",
    "traffic.xray.up_bytes",
    "xray.uplink_bytes",
    "xray_up_bytes",
  ]));
  const xrayDown = finiteNumber(pick(data, [
    "traffic.xray.downlink_bytes",
    "traffic.xray.down_bytes",
    "xray.downlink_bytes",
    "xray_down_bytes",
  ]));
  const xrayTotal = xrayUp === null && xrayDown === null ? null : (xrayUp || 0) + (xrayDown || 0);
  byId("xray-total").textContent = formatBytes(xrayTotal);
  if (xrayUp !== null || xrayDown !== null) {
    byId("xray-note").textContent = `Up ${formatBytes(xrayUp)} · down ${formatBytes(xrayDown)} · separate layer`;
  }

  renderAllowance(data);
  renderResources(data, collectedAt);
  renderPaths(pick(data, ["paths", "access_paths", "network.paths"], []));
  renderAlerts(pick(data, ["alerts", "health.alerts", "limits"], []));
}

function renderAllowance(data) {
  const allowance = finiteNumber(pick(data, [
    "traffic.aws.allowance_bytes",
    "traffic.allowance_bytes",
    "aws.allowance_bytes",
    "allowance_bytes",
  ]));
  const used = finiteNumber(pick(data, [
    "traffic.aws.transfer_used_bytes",
    "traffic.aws.used_bytes",
    "aws.transfer_used_bytes",
    "allowance_used_bytes",
  ]));
  const source = String(pick(data, ["traffic.aws.source", "aws.source", "allowance_source"], "unavailable"));
  const value = byId("allowance");
  const note = byId("allowance-note");
  if (allowance === null) {
    value.textContent = "Unavailable";
    note.textContent = "Requires AWS read-only metrics permission";
    return;
  }
  if (used === null) {
    value.textContent = formatBytes(allowance);
    note.textContent = `Configured allowance · source: ${source}`;
    return;
  }
  const percent = allowance > 0 ? Math.min(999, (used / allowance) * 100) : null;
  value.textContent = percent === null ? formatBytes(used) : `${percent.toFixed(percent >= 10 ? 1 : 2)}%`;
  note.textContent = `${formatBytes(used)} of ${formatBytes(allowance)} · source: ${source}`;
}

function renderResources(data, collectedAt) {
  const memoryUsed = pick(data, ["host.memory.used_bytes", "resources.memory.used_bytes", "memory_used_bytes"]);
  const memoryTotal = pick(data, ["host.memory.total_bytes", "resources.memory.total_bytes", "memory_total_bytes"]);
  const memoryPercent = pick(data, ["host.memory.percent", "resources.memory.percent", "memory_percent"]);
  setProgress("memory", memoryUsed, memoryTotal, memoryPercent);

  const diskUsed = pick(data, ["host.disk.used_bytes", "resources.disk.used_bytes", "disk_used_bytes"]);
  const diskTotal = pick(data, ["host.disk.total_bytes", "resources.disk.total_bytes", "disk_total_bytes"]);
  const diskPercent = pick(data, ["host.disk.percent", "resources.disk.percent", "disk_percent"]);
  setProgress("disk", diskUsed, diskTotal, diskPercent);

  const load = finiteNumber(pick(data, ["host.load_1m", "resources.load_1m", "load_1m"]));
  const cpuCount = finiteNumber(pick(data, ["host.cpu_count", "resources.cpu_count", "cpu_count"]));
  const loadPercent = load === null || !cpuCount ? null : (load / cpuCount) * 100;
  setProgress("load", null, null, loadPercent);
  byId("load-label").textContent = load === null ? "—" : load.toFixed(2);

  byId("uptime").textContent = formatDuration(pick(data, ["host.uptime_seconds", "resources.uptime_seconds", "uptime_seconds"]));
  byId("xray-health").textContent = String(pick(data, ["services.xray.status", "xray.status", "xray_status"], "Unknown"));
  const restarts = finiteNumber(pick(data, ["services.xray.restart_count", "xray.restart_count", "xray_restarts"]));
  byId("xray-restarts").textContent = restarts === null ? "—" : String(restarts);
  byId("collector-age").textContent = formatAge(collectedAt);
}

function renderPaths(rawPaths) {
  const container = byId("paths");
  container.replaceChildren();
  const paths = Array.isArray(rawPaths) ? rawPaths : [];
  if (!paths.length) {
    container.append(emptyMessage("No current path checks are available."));
    return;
  }
  for (const path of paths.slice(0, 20)) {
    if (!path || typeof path !== "object") continue;
    const row = document.createElement("div");
    row.className = "path-item";

    const name = document.createElement("div");
    name.className = "path-name";
    const strong = document.createElement("strong");
    strong.textContent = String(path.name || path.label || "Unnamed path");
    const direction = document.createElement("small");
    direction.textContent = String(path.direction || "observed");
    name.append(strong, direction);

    const route = document.createElement("div");
    route.className = "path-route";
    const hops = Array.isArray(path.route) ? path.route : Array.isArray(path.hops) ? path.hops : [];
    if (!hops.length) {
      const hop = document.createElement("span");
      hop.textContent = "Path detail unavailable";
      route.append(hop);
    } else {
      for (const hopValue of hops.slice(0, 8)) {
        const hop = document.createElement("span");
        hop.textContent = String(typeof hopValue === "object" ? hopValue.label || hopValue.name || "Layer" : hopValue);
        route.append(hop);
      }
    }

    const status = document.createElement("span");
    const statusName = String(path.status || "unknown").toLowerCase();
    status.className = `mini-status ${statusName.replace(/[^a-z]/g, "")}`;
    status.title = statusName;
    status.setAttribute("aria-label", `Status: ${statusName}`);
    row.append(name, route, status);
    container.append(row);
  }
}

function renderAlerts(rawAlerts) {
  const container = byId("alerts");
  container.replaceChildren();
  const alerts = Array.isArray(rawAlerts) ? rawAlerts : [];
  byId("alert-count").textContent = String(alerts.length);
  if (!alerts.length) {
    container.append(emptyMessage("No active alerts in the current snapshot."));
    return;
  }
  for (const alert of alerts.slice(0, 50)) {
    const item = typeof alert === "string" ? { title: alert } : alert;
    if (!item || typeof item !== "object") continue;
    const row = document.createElement("div");
    row.className = "alert-item";
    const severityName = String(item.severity || item.level || "warning").toLowerCase();
    const severity = document.createElement("span");
    severity.className = `severity ${severityName.replace(/[^a-z]/g, "")}`;
    severity.setAttribute("aria-label", `Severity: ${severityName}`);

    const copy = document.createElement("div");
    copy.className = "alert-copy";
    const title = document.createElement("strong");
    title.textContent = String(item.title || item.name || item.code || "Monitoring alert");
    copy.append(title);
    const messageValue = item.message || item.detail || item.description;
    if (messageValue) {
      const message = document.createElement("small");
      message.textContent = String(messageValue);
      copy.append(message);
    }
    const age = document.createElement("span");
    age.className = "alert-time";
    age.textContent = formatAge(item.timestamp || item.created_at || item.first_seen);
    row.append(severity, copy, age);
    container.append(row);
  }
}

function emptyMessage(message) {
  const element = document.createElement("p");
  element.className = "empty-state";
  element.textContent = message;
  return element;
}

function pointValue(point, paths) {
  const value = finiteNumber(pick(point, paths));
  return value === null || value < 0 ? 0 : value;
}

function normalisePoints(rawPoints) {
  if (!Array.isArray(rawPoints)) return [];
  return rawPoints.map((point, index) => ({
    timestamp: pick(point, ["timestamp", "captured_at", "collected_at", "time"], index),
    hostIn: pointValue(point, ["host_rx_bytes", "rx_bytes", "traffic.host.rx_bytes", "traffic.host.inbound_bytes"]),
    hostOut: pointValue(point, ["host_tx_bytes", "tx_bytes", "traffic.host.tx_bytes", "traffic.host.outbound_bytes"]),
    xray: pointValue(point, ["xray_bytes", "traffic.xray.total_bytes"])
      || pointValue(point, ["xray_up_bytes", "traffic.xray.uplink_bytes"])
        + pointValue(point, ["xray_down_bytes", "traffic.xray.downlink_bytes"]),
  })).filter((point) => point.hostIn || point.hostOut || point.xray);
}

function renderChart(points) {
  const canvas = byId("traffic-chart");
  const empty = byId("chart-empty");
  const context = canvas.getContext("2d");
  if (!context) return;
  const parentWidth = Math.max(260, canvas.parentElement.clientWidth);
  const cssHeight = 240;
  const ratio = Math.min(2, window.devicePixelRatio || 1);
  canvas.width = Math.round(parentWidth * ratio);
  canvas.height = Math.round(cssHeight * ratio);
  canvas.style.width = `${parentWidth}px`;
  canvas.style.height = `${cssHeight}px`;
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, parentWidth, cssHeight);

  if (!points.length) {
    empty.hidden = false;
    canvas.setAttribute("aria-label", "No traffic history is available");
    return;
  }
  empty.hidden = true;
  const padding = { left: 42, right: 10, top: 12, bottom: 25 };
  const width = parentWidth - padding.left - padding.right;
  const height = cssHeight - padding.top - padding.bottom;
  const maximum = Math.max(1, ...points.flatMap((point) => [point.hostIn, point.hostOut, point.xray]));

  context.lineWidth = 1;
  context.strokeStyle = "rgba(151, 178, 202, 0.13)";
  context.fillStyle = "#71889a";
  context.font = "10px ui-sans-serif, system-ui, sans-serif";
  context.textAlign = "right";
  context.textBaseline = "middle";
  for (let row = 0; row <= 4; row += 1) {
    const y = padding.top + (height * row / 4);
    context.beginPath();
    context.moveTo(padding.left, y);
    context.lineTo(parentWidth - padding.right, y);
    context.stroke();
    context.fillText(formatBytes(maximum * (1 - row / 4)), padding.left - 7, y);
  }

  const styles = getComputedStyle(document.documentElement);
  const lines = [
    ["hostIn", styles.getPropertyValue("--cyan").trim() || "#55d6d2"],
    ["hostOut", styles.getPropertyValue("--blue").trim() || "#62a8ff"],
    ["xray", styles.getPropertyValue("--violet").trim() || "#ae8bff"],
  ];
  for (const [key, color] of lines) {
    context.beginPath();
    context.lineWidth = 1.8;
    context.lineJoin = "round";
    context.lineCap = "round";
    context.strokeStyle = color;
    for (let index = 0; index < points.length; index += 1) {
      const x = padding.left + (width * index / Math.max(1, points.length - 1));
      const y = padding.top + height - (height * points[index][key] / maximum);
      if (index === 0) context.moveTo(x, y);
      else context.lineTo(x, y);
    }
    context.stroke();
  }
  canvas.setAttribute("aria-label", `${points.length} traffic samples; peak ${formatBytes(maximum)}`);
}

async function refreshOverview() {
  try {
    const data = await fetchJSON("/api/overview");
    renderOverview(data);
  } catch (error) {
    setStatus("unknown");
    setNotice(error.name === "AbortError" ? "The monitoring API timed out." : error.message);
    byId("updated").textContent = "Collector unavailable";
  }
}

async function refreshSeries() {
  try {
    const data = await fetchJSON(`/api/series?hours=${state.hours}&limit=2000`);
    state.points = normalisePoints(data.points);
    renderChart(state.points);
  } catch (error) {
    state.points = [];
    renderChart([]);
    if (!byId("notice").textContent) setNotice(error.message);
  }
}

async function refreshAll() {
  await Promise.all([refreshOverview(), refreshSeries()]);
}

function selectRange(button) {
  const hours = finiteNumber(button.dataset.hours);
  if (hours === null) return;
  state.hours = hours;
  document.querySelectorAll("[data-hours]").forEach((candidate) => {
    const active = candidate === button;
    candidate.classList.toggle("active", active);
    candidate.setAttribute("aria-pressed", String(active));
  });
  refreshSeries();
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-hours]").forEach((button) => {
    button.addEventListener("click", () => selectRange(button));
  });
  window.addEventListener("resize", () => renderChart(state.points));
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refreshAll();
  });
  refreshAll();
  state.refreshTimer = window.setInterval(() => {
    if (!document.hidden) refreshAll();
  }, REFRESH_MS);
});
