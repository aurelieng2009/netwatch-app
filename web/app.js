import {
  lineChart, heatmap, sparkline, uptimeStrip, fmtMs, fmtDateTime, uptimeColor, cssVar,
} from "./charts.js";

// ------------------------------------------------------------------ utilitaires
const $ = (s, r = document) => r.querySelector(s);
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts = {}) {
  const r = await fetch(`/api/${path}`, {
    headers: opts.body ? { "Content-Type": "application/json" } : {},
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (r.status === 401) {
    showLogin("Session expirée. Reconnecte-toi.");
    throw new Error("401 non authentifié");
  }
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

function ago(ts) {
  if (!ts) return "jamais";
  const s = Math.round(Date.now() / 1000 - ts);
  if (s < 0) return `dans ${fmtDur(-s)}`;
  if (s < 45) return "à l'instant";
  return `il y a ${fmtDur(s)}`;
}
function fmtDur(s) {
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${pad(Math.round((s % 3600) / 60))}`;
  return `${Math.floor(s / 86400)} j ${Math.floor((s % 86400) / 3600)} h`;
}
const pad = (n) => String(n).padStart(2, "0");
const pct = (v, d = 1) => (v == null ? "—" : `${v.toFixed(d)} %`);

function toast(html, ms = 6000) {
  const d = document.createElement("div");
  d.innerHTML = html;
  $("#toast").appendChild(d);
  setTimeout(() => d.remove(), ms);
}

// ------------------------------------------------------------------ icônes
const P = {
  dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  devices: '<rect x="2" y="4" width="20" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  heat: '<path d="M3 3v18h18"/><path d="M7 14l4-4 3 3 5-6"/>',
  bell: '<path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.9 1.9 0 0 0 3.4 0"/>',
  radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6-6"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.4L21 8"/><path d="M21 3v5h-5"/>',
  back: '<path d="M15 18l-6-6 6-6"/>',
  router: '<rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 17h.01M10 17h.01M15 9a4 4 0 0 1 6 0M17 11a1.5 1.5 0 0 1 2 0M12 13V7"/>',
  switch: '<rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 12h.01M9 12h.01M12 12h.01M15 12h.01M18 12h.01"/>',
  server: '<rect x="3" y="3" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" height="7" rx="1.5"/><path d="M7 6.5h.01M7 17.5h.01"/>',
  nas: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  desktop: '<rect x="2" y="3" width="20" height="13" rx="2"/><path d="M8 21h8M12 16v5"/>',
  laptop: '<rect x="4" y="4" width="16" height="11" rx="1.5"/><path d="M2 19h20"/>',
  phone: '<rect x="7" y="2" width="10" height="20" rx="2.5"/><path d="M11 18h2"/>',
  tablet: '<rect x="4" y="2" width="16" height="20" rx="2.5"/><path d="M11 18h2"/>',
  iot: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
  camera: '<path d="M3 7h3l2-3h8l2 3h3v12H3z"/><circle cx="12" cy="13" r="4"/>',
  media: '<rect x="2" y="4" width="20" height="13" rx="2"/><path d="M7 21h10"/>',
  console: '<path d="M6 11h4M8 9v4M15 12h.01M18 10h.01"/><rect x="2" y="6" width="20" height="12" rx="6"/>',
  printer: '<path d="M6 9V2h12v7"/><rect x="2" y="9" width="20" height="8" rx="2"/><rect x="6" y="14" width="12" height="8"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
  other: '<circle cx="12" cy="12" r="9"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01"/>',
  scan: '<path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2M7 12h10"/>',
  trash: '<path d="M3 6h18M8 6V4h8v2M6 6l1 15h10l1-15"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
  warn: '<path d="M12 3l10 18H2z"/><path d="M12 10v4M12 17.5h.01"/>',
  crit: '<circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/>',
  diag: '<path d="M4 3v7a5 5 0 0 0 10 0V3"/><path d="M9 20a3 3 0 0 0 6 0v-3"/><circle cx="18" cy="15" r="2.5"/>',
  key: '<circle cx="8" cy="14" r="4"/><path d="M11 11l9-9M17 5l3 3M14 8l2 2"/>',
  conflict: '<path d="M12 3l10 18H2z"/><path d="M12 9v4M12 17.5h.01"/>',
  cpu: '<rect x="6" y="6" width="12" height="12" rx="1.5"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
  disk: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/>',
  wifi: '<path d="M5 12.5a10 10 0 0 1 14 0M8 15.5a6 6 0 0 1 8 0M12 19h.01"/>',
  wired: '<path d="M6 3v6M18 3v6M4 9h16v3a8 8 0 0 1-16 0z M12 20v-3"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  push: '<rect x="5" y="2" width="11" height="20" rx="2.5"/><path d="M9 18h3"/><path d="M18.5 5a5 5 0 0 1 0 7M21 3a8 8 0 0 1 0 11"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
};
const icon = (name, size = 18) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || P.other}</svg>`;

const TYPES = {
  router: "Routeur / box", switch: "Switch / AP", server: "Serveur / VM", nas: "NAS",
  desktop: "PC fixe", laptop: "Portable", phone: "Téléphone", tablet: "Tablette",
  iot: "Objet connecté", camera: "Caméra", media: "TV / multimédia", console: "Console",
  printer: "Imprimante", other: "Autre",
};
function guessType(d) {
  if (d.kind === "external") return "globe";
  if (d.dev_type) return d.dev_type;
  if (d.is_gateway) return "router";
  const v = (d.vendor || "").toLowerCase();
  const n = (d.name || "").toLowerCase();
  if (/iphone|pixel|galaxy|android|phone/.test(n) || d.random_mac) return "phone";
  if (/ipad|tab/.test(n)) return "tablet";
  if (/espressif|tuya|shelly|sonoff|texas instr|silicon lab/.test(v)) return "iot";
  if (/reolink|hikvision|dahua|axis|amcrest/.test(v)) return "camera";
  if (/synology|qnap|western digital/.test(v)) return "nas";
  if (/proxmox|vmware|qemu|xensource|super micro/.test(v)) return "server";
  if (/nintendo|sony interactive|microsoft/.test(v)) return "console";
  if (/hewlett|brother|canon|epson/.test(v)) return "printer";
  if (/ubiquiti|tp-link|netgear|cisco|mikrotik|aruba/.test(v)) return "switch";
  if (/samsung|lg elec|google|roku|sonos|amazon/.test(v)) return "media";
  if (/apple/.test(v)) return "laptop";
  if (/raspberry/.test(v)) return "server";
  return "other";
}

const EV_LABEL = {
  new_device: "Nouvel appareil", device_offline: "Hors ligne", device_online: "En ligne",
  port_opened: "Port ouvert", port_closed: "Port fermé", high_latency: "Latence élevée",
  latency_ok: "Latence normale", ip_changed: "Changement d'IP", inventory: "Inventaire",
  ip_conflict: "Conflit d'IP", latency_anomaly: "Latence suspecte", diag_finding: "Diagnostic",
  ssh_hostkey_changed: "Clé SSH modifiée", ssh_inventory: "Inventaire SSH",
  gateway_mac_changed: "MAC passerelle modifiée", security_finding: "Sécurité", rogue_dhcp: "DHCP pirate",
  bbox_reboot: "Box redémarrée", bbox_internet: "Internet (box)", bbox_auth: "Box : accès refusé", bbox_firmware: "Firmware de la box", wifi_channel: "Canal Wi-Fi modifié",
  z2m_bridge: "Zigbee2MQTT",
};
const bytes = (n) => {
  if (n == null) return "—";
  const u = ["o", "Ko", "Mo", "Go", "To"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
};
const sevIcon = (s) => `<span class="sev ${esc(s)}">${icon(s === "critical" ? "crit" : s === "warning" ? "warn" : "info", 14)}</span>`;

function eventList(events, withDevice = true) {
  if (!events.length) return `<div class="empty">Aucun événement</div>`;
  return `<ul class="events">${events.map((e) => `
    <li>${sevIcon(e.severity)}
      <div class="msg">${
        withDevice && e.device_id ? `<a href="#/device/${e.device_id}">${esc(e.message)}</a>` : esc(e.message)
      }<div class="type">${esc(EV_LABEL[e.type] || e.type)}</div></div>
      <span class="when" title="${fmtDateTime(e.ts)}">${ago(e.ts)}</span>
    </li>`).join("")}</ul>`;
}

const segHTML = (id, options, current) =>
  `<div class="seg" id="${id}">${options.map(([k, l]) => `<button data-k="${k}" class="${k === current ? "on" : ""}">${l}</button>`).join("")}</div>`;
function bindSeg(id, cb) {
  const s = document.getElementById(id);
  if (!s) return;
  s.addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    s.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
    cb(b.dataset.k);
  });
}
const RANGES = [["1h", "1 h"], ["6h", "6 h"], ["24h", "24 h"], ["7d", "7 j"], ["30d", "30 j"]];
const prefs = {
  get(k, d) { try { return localStorage.getItem("nw-" + k) || d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem("nw-" + k, v); } catch { /* ignore */ } },
};

// ------------------------------------------------------------------ état global
const state = { overview: null, page: null, refresh: null };

function renderNav() {
  const o = state.overview;
  const route = location.hash || "#/";
  const items = [
    ["#/", "dashboard", "Tableau de bord"],
    ["#/devices", "devices", "Appareils", o ? `<span class="count ${o.devices.unknown ? "warn" : ""}">${o.devices.unknown ? o.devices.unknown + " nouv." : o.devices.online}</span>` : ""],
    ["#/latency", "heat", "Latence"],
    ["#/diagnostic", "diag", "Diagnostic", o && (o.findings?.active || o.conflicts) ? `<span class="count ${o.findings?.critical || o.conflicts ? "warn" : ""}">${(o.findings?.active || 0) + (o.conflicts || 0)}</span>` : ""],
    ["#/events", "bell", "Événements", o && o.events_24h.warnings ? `<span class="count warn">${o.events_24h.warnings}</span>` : ""],
    ["#/scans", "radar", "Scans"],
    ["#/notifications", "push", "Notifications"],
    ["#/box", "router", "Box"],
    ["#/wifi", "radar", "Wi-Fi"],
    ["#/radio", "radar", "Radio"],
    ["#/zigbee", "iot", "Zigbee"],
    ["#/credentials", "key", "Identifiants", o && o.ssh?.locked ? '<span class="count warn">!</span>' : ""],
    ["#/settings", "gear", "Réglages"],
  ];
  $("#nav").innerHTML = items.map(([h, ic, l, extra = ""]) => {
    const active = h === "#/" ? route === "#/" || route === "#" : route.startsWith(h) || (h === "#/devices" && route.startsWith("#/device/"));
    return `<a href="${h}" class="${active ? "active" : ""}">${icon(ic)}<span class="label-long">${l}</span>${extra}</a>`;
  }).join("");
  if (o) {
    $("#side-foot").innerHTML = `
      <div>${icon("globe", 13)} ${esc(o.network.subnet || "?")} · ${esc(o.network.interface)}</div>
      <div>Scanner : ${esc(o.network.ip || "?")}</div>
      ${o.demo ? '<div class="badge new">Mode démo</div>' : ""}`;
  }
}

function renderLive() {
  const o = state.overview;
  const live = $("#live");
  if (!o) return;
  const d = o.status.discovery;
  const deep = o.status.deep;
  const busy = d.running || deep.running || deep.queued;
  live.className = `live ${sse.connected ? (busy ? "busy" : "on") : ""}`;
  let txt = d.running ? "Découverte…" : `Découverte ${ago(d.last)}`;
  if (deep.running || deep.queued) txt += ` · nmap ${deep.running} en cours, ${deep.queued} en file`;
  $("#live-txt").textContent = sse.connected ? txt : "Hors connexion";
}

async function loadOverview() {
  try {
    state.overview = await api("overview");
    renderNav();
    renderLive();
  } catch (e) {
    console.warn(e);
  }
}

// ------------------------------------------------------------------ page : tableau de bord
async function pageDashboard(root) {
  $("#page-title").textContent = "Tableau de bord";
  let range = prefs.get("dash-range", "24h");
  root.innerHTML = `
    ${state.overview?.demo ? `<div class="banner">Mode démo : les données sont simulées. Désactivez <span class="mono">NETWATCH_DEMO</span> pour scanner votre réseau.</div>` : ""}
    <div class="grid kpis" id="kpis"></div>
    <div class="grid cols-3-1" style="margin-bottom:16px">
      <div class="card"><div class="card-h"><h2>Latence Internet et passerelle</h2><div class="right">${segHTML("r-dash", RANGES, range)}</div></div>
        <div id="ch-ext"></div></div>
      <div class="card"><div class="card-h"><h2>Derniers événements</h2><div class="right"><a href="#/events">Tout voir</a></div></div>
        <div id="ev-list" style="max-height:290px;overflow:auto"></div></div>
    </div>
    <div class="grid cols-2">
      <div class="card"><div class="card-h"><h2>Appareils en ligne</h2><span class="sub" id="online-sub"></span></div><div id="ch-online"></div></div>
      <div class="card"><div class="card-h"><h2>Latence moyenne LAN</h2><span class="sub">moyenne des appareils joignables en ICMP</span></div><div id="ch-lan"></div></div>
    </div>
    <div class="card" style="margin-top:16px"><div class="card-h"><h2>Appareils les plus lents</h2><span class="sub">dernière mesure</span><div class="right"><a href="#/latency">Heatmap</a></div></div>
      <div class="table-wrap"><table><tbody id="slow"></tbody></table></div></div>`;

  const drawKpis = () => {
    const o = state.overview;
    if (!o) return;
    const ext = o.external.filter((e) => e.latency != null);
    const extAvg = ext.length ? ext.reduce((a, e) => a + e.latency, 0) / ext.length : null;
    const extDown = o.external.filter((e) => !e.online).length;
    $("#kpis").innerHTML = `
      <div class="card kpi"><div class="label">${icon("devices", 15)} Appareils en ligne</div>
        <div class="value">${o.devices.online}<small>/ ${o.devices.total}</small></div>
        <div class="foot">${o.devices.new_24h} nouveau(x) sur 24 h</div></div>
      <div class="card kpi ${o.devices.unknown ? "alert" : ""}"><div class="label">${icon("warn", 15)} Non approuvés</div>
        <div class="value">${o.devices.unknown}</div>
        <div class="foot">${o.devices.unknown ? '<a href="#/devices?f=unknown">À vérifier</a>' : "Tout est connu"}</div></div>
      <div class="card kpi ${o.devices.watched_offline ? "alert" : ""}"><div class="label">${icon("radar", 15)} Surveillés</div>
        <div class="value">${o.devices.watched - o.devices.watched_offline}<small>/ ${o.devices.watched}</small></div>
        <div class="foot">Disponibilité 24 h : ${pct(o.watched_availability_24h, 2)}</div></div>
      <div class="card kpi"><div class="label">${icon("router", 15)} Passerelle</div>
        <div class="value">${fmtMs(o.latency.gateway)}</div>
        <div class="foot">LAN moy. ${fmtMs(o.latency.lan_avg)} · max ${fmtMs(o.latency.lan_max)}</div></div>
      <div class="card kpi ${extDown ? "alert" : ""}"><div class="label">${icon("globe", 15)} Internet</div>
        <div class="value">${fmtMs(extAvg)}</div>
        <div class="foot">${extDown ? `<span style="color:var(--critical-text)">${extDown} cible(s) injoignable(s)</span>` : o.external.map((e) => `${esc(e.ip)} ${fmtMs(e.latency)}`).join(" · ")}</div></div>
      <div class="card kpi"><div class="label">${icon("scan", 15)} Ports ouverts</div>
        <div class="value">${o.open_ports}</div>
        <div class="foot">Scan nmap ${ago(o.status.deep.last)}</div></div>`;
  };

  const drawCharts = async () => {
    const m = await api(`metrics/overview?range=${range}`);
    const colors = ["--s1", "--s2", "--s3", "--s4"];
    lineChart($("#ch-ext"), {
      t: m.grid, height: 250, yFmt: (v) => `${v} ms`, tipFmt: fmtMs, label: "Latence Internet",
      series: m.targets.map((tg, i) => ({ name: tg.label, values: tg.latency, color: colors[i % 4] })),
    });
    const s = m.series;
    lineChart($("#ch-online"), {
      t: s.t, height: 200, yFmt: (v) => String(v), tipFmt: (v) => v.toFixed(1), label: "Appareils en ligne",
      series: [{ name: "En ligne", values: s.online, color: "--s1", area: true }],
    });
    lineChart($("#ch-lan"), {
      t: s.t, height: 200, yFmt: (v) => `${v} ms`, tipFmt: fmtMs, label: "Latence LAN",
      series: [{ name: "Latence LAN", values: s.lan_latency, color: "--s3" }],
    });
    const last = s.total.filter((x) => x != null).pop();
    $("#online-sub").textContent = last ? `${last} appareils actifs sur 24 h` : "";
  };

  const drawLists = async () => {
    const [events, devices] = await Promise.all([api("events?limit=15"), api("devices")]);
    $("#ev-list").innerHTML = eventList(events);
    const slow = devices.filter((d) => d.kind === "lan" && d.online && d.last_latency != null)
      .sort((a, b) => b.last_latency - a.last_latency).slice(0, 6);
    $("#slow").innerHTML = slow.map((d) => `
      <tr data-href="#/device/${d.id}" style="cursor:pointer">
        <td><span class="name">${esc(d.name)}</span><div class="sub mono">${esc(d.ip)}</div></td>
        <td class="t2">${esc(d.vendor || "")}</td>
        <td>${sparkline(d.spark)}</td>
        <td class="num" style="text-align:right">${fmtMs(d.last_latency)}${d.last_loss ? ` <span class="badge crit">${d.last_loss} % perte</span>` : ""}</td>
      </tr>`).join("") || `<tr><td class="empty">—</td></tr>`;
  };

  bindSeg("r-dash", (k) => { range = k; prefs.set("dash-range", k); drawCharts(); });
  drawKpis();
  await Promise.all([drawCharts(), drawLists()]);
  state.refresh = async () => { drawKpis(); await Promise.all([drawCharts(), drawLists()]); };
}

// ------------------------------------------------------------------ page : appareils
async function pageDevices(root, params) {
  $("#page-title").textContent = "Appareils";
  let filter = params.get("f") || "all";
  let sortKey = prefs.get("dev-sort", "ip");
  let sortDir = 1;
  let q = "";
  root.innerHTML = `
    <div class="toolbar">
      <input type="search" id="q" placeholder="Rechercher nom, IP, MAC, constructeur, OS…" autocomplete="off">
      ${segHTML("f-dev", [["all", "Tous"], ["online", "En ligne"], ["offline", "Hors ligne"], ["unknown", "Non approuvés"], ["watch", "Surveillés"], ["external", "Internet"]], filter)}
      <div class="spacer" style="flex:1"></div>
      <button class="btn" id="deep-all">${icon("scan", 15)} Scan nmap de tout le réseau</button>
    </div>
    <div class="card" style="padding-top:4px;padding-bottom:4px"><div class="table-wrap"><table>
      <thead><tr>
        <th data-s="status">État</th><th data-s="name">Appareil</th><th data-s="ip">IP</th><th data-s="mac">MAC / constructeur</th>
        <th data-s="lat">Latence (1 h)</th><th data-s="ports">Ports</th><th data-s="os">OS</th><th data-s="seen">Vu</th>
      </tr></thead><tbody id="dev-body"></tbody></table></div></div>
    <p class="muted" id="dev-count" style="font-size:12.5px"></p>`;
  let devices = [];

  const ipNum = (ip) => (ip || "").split(".").reduce((a, b) => a * 256 + (+b || 0), 0);
  const keyFns = {
    status: (d) => (d.online ? 0 : 1), name: (d) => (d.name || "").toLowerCase(), ip: (d) => (d.kind === "lan" ? 0 : 1e12) + ipNum(d.ip),
    mac: (d) => d.mac, lat: (d) => d.last_latency ?? 1e9, ports: (d) => -d.open_ports, os: (d) => d.os_name || "~",
    seen: (d) => -(d.last_seen || 0),
  };
  const draw = () => {
    const ql = q.toLowerCase();
    let rows = devices.filter((d) => {
      if (filter === "online" && !d.online) return false;
      if (filter === "offline" && d.online) return false;
      if (filter === "unknown" && (d.known || d.kind !== "lan")) return false;
      if (filter === "watch" && !d.watch) return false;
      if (filter === "external" && d.kind !== "external") return false;
      if (filter !== "external" && filter !== "all" && d.kind === "external" && filter !== "watch") return false;
      if (!ql) return true;
      return [d.name, d.hostname, d.alias, d.ip, d.mac, d.vendor, d.os_name, d.notes].some((x) => (x || "").toLowerCase().includes(ql));
    });
    const fn = keyFns[sortKey] || keyFns.ip;
    rows.sort((a, b) => (fn(a) > fn(b) ? 1 : fn(a) < fn(b) ? -1 : 0) * sortDir);
    document.querySelectorAll("th[data-s]").forEach((th) => th.classList.toggle("sorted", th.dataset.s === sortKey));
    $("#dev-body").innerHTML = rows.map((d) => {
      const t = guessType(d);
      const badges = [
        d.kind === "lan" && !d.known ? '<span class="badge new">nouveau</span>' : "",
        d.watch ? '<span class="badge watch">surveillé</span>' : "",
        d.excluded ? '<span class="badge crit">exclu</span>' : "",
        d.is_gateway ? '<span class="badge">passerelle</span>' : "",
        d.is_self ? '<span class="badge">ce serveur</span>' : "",
      ].join(" ");
      return `<tr data-id="${d.id}">
        <td><span class="status ${d.online ? "on" : "off"}"><i></i>${d.online ? "En ligne" : "Hors ligne"}</span></td>
        <td><div style="display:flex;gap:10px;align-items:center"><span class="t2">${icon(t, 18)}</span>
          <div><span class="name">${esc(d.name)}</span> ${badges}
          <div class="sub">${d.alias && d.hostname ? esc(d.hostname) + " · " : ""}${esc(TYPES[d.dev_type] || "")}</div></div></div></td>
        <td class="mono">${esc(d.ip)}</td>
        <td>${d.kind === "lan" ? `<span class="mono">${esc(d.mac)}</span><div class="sub">${d.random_mac ? "MAC aléatoire (privée)" : esc(d.vendor || "constructeur inconnu")}</div>` : '<span class="muted">cible externe</span>'}</td>
        <td><div style="display:flex;align-items:center;gap:8px">${sparkline(d.spark)}<span class="num t2">${fmtMs(d.last_latency)}</span></div></td>
        <td class="num">${d.open_ports || (d.last_deep_scan ? "0" : '<span class="muted">—</span>')}</td>
        <td class="t2" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(d.os_name || "")}</td>
        <td class="t2" title="${d.last_seen ? fmtDateTime(d.last_seen) : ""}">${d.online ? "maintenant" : ago(d.last_seen)}</td>
      </tr>`;
    }).join("") || `<tr><td colspan="8" class="empty">Aucun appareil ne correspond</td></tr>`;
    $("#dev-count").textContent = `${rows.length} appareil(s) affiché(s) sur ${devices.length}`;
  };
  const load = async () => { devices = await api("devices"); draw(); };

  $("#q").addEventListener("input", (e) => { q = e.target.value; draw(); });
  bindSeg("f-dev", (k) => { filter = k; draw(); });
  $("#dev-body").addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (tr) location.hash = `#/device/${tr.dataset.id}`;
  });
  root.querySelector("thead").addEventListener("click", (e) => {
    const th = e.target.closest("th[data-s]");
    if (!th) return;
    if (sortKey === th.dataset.s) sortDir = -sortDir; else { sortKey = th.dataset.s; sortDir = 1; }
    prefs.set("dev-sort", sortKey);
    draw();
  });
  $("#deep-all").addEventListener("click", async (e) => {
    e.target.disabled = true;
    const r = await api("scan/deep", { method: "POST" });
    toast(r.queued ? `Scan nmap lancé sur ${r.hosts} appareil(s)` : "Scan déjà en file d'attente");
    loadOverview();
  });
  await load();
  state.refresh = load;
}

// ------------------------------------------------------------------ page : fiche appareil
async function pageDevice(root, id) {
  let range = prefs.get("dev-range", "24h");
  const d = await api(`devices/${id}`);
  $("#page-title").textContent = d.name;
  const t = guessType(d);
  const names = Object.entries(d.names || {}).map(([k, v]) => `<span class="badge" title="source : ${esc(k)}">${esc(k)} : ${esc(v)}</span>`).join(" ");

  root.innerHTML = `
    <div style="margin-bottom:12px"><a href="#/devices" class="t2" style="display:inline-flex;align-items:center;gap:4px">${icon("back", 15)} Appareils</a></div>
    <div class="dev-head">
      <div class="dev-icon">${icon(t, 26)}</div>
      <div class="dev-title" style="flex:1;min-width:240px">
        <h2 id="dev-name">${esc(d.name)}</h2>
        <div class="meta" id="dev-meta"></div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        ${d.kind === "lan" ? `<button class="btn primary" id="btn-scan">${icon("scan", 15)} Scan nmap</button>` : ""}
        ${d.kind === "lan" ? `<button class="btn" id="btn-exclude">${icon(d.excluded ? "radar" : "warn", 15)} ${d.excluded ? "Réintégrer au scan" : "Exclure du scan"}</button>` : ""}
        ${d.kind === "lan" ? `<button class="btn danger" id="btn-del">${icon("trash", 15)} Oublier</button>` : ""}
      </div>
    </div>
    <div id="dev-alerts"></div>
    <div class="grid cols-3-1">
      <div style="display:flex;flex-direction:column;gap:16px;min-width:0">
        <div class="card">
          <div class="card-h"><h2>Latence</h2><div class="right">${segHTML("r-dev", RANGES, range)}</div></div>
          <div class="stat-row" id="dev-stats"></div>
          <div id="ch-lat"></div>
        </div>
        <div class="card">
          <div class="card-h"><h2>Disponibilité</h2><span class="sub" id="avail-sub"></span></div>
          <div id="strip"></div>
          <div class="scale" style="margin-top:10px;gap:14px;flex-wrap:wrap">
            ${[[1, "≥ 99 %"], [0.95, "90–99 %"], [0.6, "50–90 %"], [0.1, "< 50 %"], [null, "pas de données"]].map(([v, l]) => `<span style="display:inline-flex;gap:6px;align-items:center"><i style="width:10px;height:10px;border-radius:2px;background:${uptimeColor(v)}"></i>${l}</span>`).join("")}
          </div>
        </div>
        ${d.kind === "lan" ? `<div class="card"><div class="card-h"><h2>Ports et services</h2><span class="sub" id="ports-sub"></span></div>
          <div class="table-wrap"><table class="table-plain"><thead><tr><th>Port</th><th>Service</th><th>Produit / version</th><th>Vu depuis</th></tr></thead><tbody id="ports"></tbody></table></div></div>` : ""}
        ${d.kind === "lan" ? `<div id="ssh-card"></div>` : ""}
      </div>
      <div style="display:flex;flex-direction:column;gap:16px;min-width:0">
        <div class="card"><div class="card-h"><h2>Informations</h2></div><dl class="kv" id="dev-info"></dl>
          ${names ? `<div style="margin-top:12px;display:flex;gap:6px;flex-wrap:wrap">${names}</div>` : ""}</div>
        <div class="card"><div class="card-h"><h2>Réglages</h2><span class="sub" id="save-state"></span></div>
          <div class="form-row"><span>Nom personnalisé</span><input type="text" id="f-alias" placeholder="${esc(d.hostname || d.ip || "")}" value="${esc(d.alias || "")}"></div>
          <div class="form-row"><span>Type</span><select id="f-type"><option value="">Automatique</option>${Object.entries(TYPES).map(([k, l]) => `<option value="${k}" ${d.dev_type === k ? "selected" : ""}>${l}</option>`).join("")}</select></div>
          <div class="form-row"><label class="check"><span class="switch"><input type="checkbox" id="f-known" ${d.known ? "checked" : ""}><span></span></span>Appareil connu (approuvé)</label></div>
          <div class="form-row"><label class="check"><span class="switch"><input type="checkbox" id="f-watch" ${d.watch ? "checked" : ""}><span></span></span>Surveiller (alertes hors ligne / latence)</label></div>
          <div class="form-row"><span>Notes</span><textarea id="f-notes">${esc(d.notes || "")}</textarea></div>
          <button class="btn primary" id="btn-save">Enregistrer</button>
        </div>
        <div class="card"><div class="card-h"><h2>Historique</h2></div><div id="dev-events" style="max-height:360px;overflow:auto"></div></div>
      </div>
    </div>`;

  const drawInfo = (d) => {
    $("#dev-meta").innerHTML = `
      <span class="status ${d.online ? "on" : "off"}"><i></i>${d.online ? "En ligne" : `Hors ligne · vu ${ago(d.last_seen)}`}</span>
      <span class="mono">${esc(d.ip)}</span>
      ${d.kind === "lan" ? `<span class="mono">${esc(d.mac)}</span>` : ""}
      ${!d.known && d.kind === "lan" ? '<span class="badge new">non approuvé</span>' : ""}
      ${d.watch ? '<span class="badge watch">surveillé</span>' : ""}
      ${d.excluded ? '<span class="badge crit">exclu du scan</span>' : ""}
      ${d.deep_pending ? '<span class="badge">scan nmap en cours…</span>' : ""}`;
    const rows = [
      ["Nom d'hôte", d.hostname ? `${esc(d.hostname)} <span class="muted">(${esc(d.hostname_source)})</span>` : '<span class="muted">non résolu</span>'],
      ["Constructeur", d.random_mac ? "MAC aléatoire (appareil mobile probable)" : esc(d.vendor || "inconnu")],
      ["Système", d.os_name ? `${esc(d.os_name)} <span class="muted">(${d.os_accuracy} %)</span>` : '<span class="muted">—</span>'],
      ["Première vue", d.first_seen ? `${fmtDateTime(d.first_seen)} <span class="muted">(${ago(d.first_seen)})</span>` : "—"],
      ["Dernière vue", d.online ? "maintenant" : ago(d.last_seen)],
      ["Dernier scan nmap", d.last_deep_scan ? ago(d.last_deep_scan) : "jamais"],
    ];
    if (d.kind === "external") rows.splice(1, 5, ["Rôle", "Cible de latence Internet"]);
    $("#dev-info").innerHTML = rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
    const s = d.stats_24h || {};
    $("#dev-stats").innerHTML = `
      <div>Actuelle<b>${fmtMs(d.last_latency)}</b></div>
      <div>Moy. 24 h<b>${fmtMs(s.avg)}</b></div>
      <div>Min / max 24 h<b>${fmtMs(s.mn)} / ${fmtMs(s.mx)}</b></div>
      <div>Perte moy. 24 h<b>${s.loss == null ? "—" : s.loss.toFixed(1) + " %"}</b></div>
      <div>Dispo. 24 h<b>${pct(d.availability_24h, 2)}</b></div>
      <div>Dispo. 7 j<b>${pct(d.availability_7d, 2)}</b></div>`;
    if ($("#ports")) {
      const open = d.ports.filter((p) => p.open);
      $("#ports-sub").textContent = d.last_deep_scan ? `${open.length} ouvert(s) · scan ${ago(d.last_deep_scan)}` : "pas encore scanné";
      $("#ports").innerHTML = d.ports.map((p) => `
        <tr style="${p.open ? "" : "opacity:.45"}">
          <td class="mono">${p.port}/${esc(p.proto)} ${p.open ? "" : '<span class="badge">fermé</span>'}</td>
          <td>${esc(p.service || "")}</td>
          <td class="t2">${esc([p.product, p.version, p.extra].filter(Boolean).join(" "))}</td>
          <td class="t2" title="${fmtDateTime(p.first_seen)}">${ago(p.first_seen)}</td>
        </tr>`).join("") || `<tr><td colspan="4" class="empty">${d.last_deep_scan ? "Aucun port TCP ouvert détecté" : "Lancez un scan nmap pour découvrir les services"}</td></tr>`;
    }
    $("#dev-events").innerHTML = eventList(d.events, false);
    if ($("#ssh-card")) $("#ssh-card").innerHTML = sshCard(d);
    if ($("#dev-alerts")) {
      $("#dev-alerts").innerHTML = (d.conflicts || []).map((c) => `<div class="finding sev-critical"><div class="finding-h">${sevIcon("critical")}<b>Conflit d'IP sur ${esc(c.ip)}</b></div><div class="finding-d">${(c.macs || []).length} MAC en concurrence : ${(c.macs || []).map(esc).join(", ")}</div></div>`).join("")
        + (d.findings || []).map(findingCard).join("");
    }
  };

  const drawCharts = async () => {
    const m = await api(`devices/${id}/metrics?range=${range}`);
    lineChart($("#ch-lat"), {
      t: m.t, height: 240, yFmt: (v) => `${v} ms`, tipFmt: fmtMs, label: "Latence",
      series: [{ name: "Latence moyenne", values: m.latency, color: "--s1" }],
      band: { lo: m.lat_min, hi: m.lat_max, color: "--s1" },
      extraTip: (i) => (m.loss[i] ? `<div class="tt-r" style="color:var(--critical-text)">perte<b>${m.loss[i]} %</b></div>` : ""),
    });
    if (!m.latency.some((v) => v != null) && m.up.some((v) => v)) {
      $("#ch-lat").insertAdjacentHTML("afterbegin", `<p class="muted" style="margin:0 0 6px;font-size:12.5px">Cet appareil répond à l'ARP mais pas au ping ICMP : présence suivie, latence non mesurable.</p>`);
    }
    uptimeStrip($("#strip"), m.t, m.up);
    const vals = m.up.filter((v) => v != null);
    $("#avail-sub").textContent = vals.length ? `${(100 * vals.reduce((a, b) => a + b, 0) / vals.length).toFixed(2)} % sur la période` : "";
  };

  drawInfo(d);
  await drawCharts();
  bindSeg("r-dev", (k) => { range = k; prefs.set("dev-range", k); drawCharts(); });

  $("#btn-save").addEventListener("click", async () => {
    const body = {
      alias: $("#f-alias").value || null, dev_type: $("#f-type").value || null,
      known: $("#f-known").checked, watch: $("#f-watch").checked, notes: $("#f-notes").value || null,
    };
    const upd = await api(`devices/${id}`, { method: "PATCH", body });
    $("#dev-name").textContent = upd.name;
    $("#page-title").textContent = upd.name;
    $("#save-state").textContent = "Enregistré ✓";
    setTimeout(() => ($("#save-state").textContent = ""), 2500);
    const fresh = await api(`devices/${id}`);
    drawInfo(fresh);
    loadOverview();
  });
  $("#btn-scan")?.addEventListener("click", async (e) => {
    e.currentTarget.disabled = true;
    const r = await api(`devices/${id}/scan`, { method: "POST" });
    toast(r.queued ? "Scan nmap ajouté à la file" : "Un scan est déjà prévu pour cet appareil");
    drawInfo(await api(`devices/${id}`));
  });
  $("#btn-exclude")?.addEventListener("click", async () => {
    const upd = await api(`devices/${id}`, { method: "PATCH", body: { excluded: !d.excluded } });
    d.excluded = upd.excluded;
    toast(upd.excluded
      ? "Appareil exclu : plus aucun scan (ARP, ping, nmap, SSH). Il reste visible ici."
      : "Appareil réintégré au scan");
    const b = $("#btn-exclude");
    b.innerHTML = `${icon(upd.excluded ? "radar" : "warn", 15)} ${upd.excluded ? "Réintégrer au scan" : "Exclure du scan"}`;
    drawInfo(await api(`devices/${id}`));
  });
  $("#btn-del")?.addEventListener("click", async () => {
    // confirmation en deux clics (pas de boîte de dialogue bloquante)
    const b = $("#btn-del");
    if (b.dataset.confirm !== "1") {
      b.dataset.confirm = "1";
      b.innerHTML = `${icon("trash", 15)} Confirmer la suppression`;
      setTimeout(() => { b.dataset.confirm = ""; b.innerHTML = `${icon("trash", 15)} Oublier`; }, 4000);
      return;
    }
    await api(`devices/${id}`, { method: "DELETE" });
    toast("Appareil oublié (il réapparaîtra s'il est de nouveau détecté)");
    location.hash = "#/devices";
  });
  state.refresh = async () => { drawInfo(await api(`devices/${id}`)); await drawCharts(); };
}

// ------------------------------------------------------------------ carte inventaire SSH
const SSH_STATUS = {
  ok: ["En ligne", "on"], auth_failed: ["Authentification refusée", "off"],
  no_credential: ["Aucun identifiant applicable", "off"], hostkey_changed: ["Clé d'hôte modifiée !", "off"],
  timeout: ["Délai dépassé", "off"], unreachable: ["Injoignable", "off"], error: ["Erreur", "off"],
};
function sshCard(d) {
  const s = d.ssh;
  if (!s) {
    return `<div class="card"><div class="card-h"><h2>${icon("key", 16)} Inventaire SSH</h2></div>
      <div class="empty" style="padding:16px">Pas encore d'inventaire SSH. Ajoutez un identifiant couvrant cette IP dans <a href="#/credentials">Identifiants</a>.</div></div>`;
  }
  const [label, cls] = SSH_STATUS[s.status] || [s.status, "off"];
  if (s.status !== "ok" || !s.inventory) {
    const warn = s.status === "hostkey_changed";
    return `<div class="card ${warn ? "sev-critical" : ""}"><div class="card-h"><h2>${icon("key", 16)} Inventaire SSH</h2>
      <span class="status ${cls}"><i></i>${esc(label)}</span></div>
      <div class="finding-d" style="padding:4px 2px 8px">${esc(s.error || "")}${warn ? " — inventaire suspendu par sécurité." : ""}</div></div>`;
  }
  const i = s.inventory;
  const mem = i.memory || {};
  const memUsed = mem.total && mem.available != null ? mem.total - mem.available : null;
  const memPct = mem.total && memUsed != null ? Math.round((memUsed / mem.total) * 100) : null;
  const kv = (k, v) => v == null || v === "" ? "" : `<dt>${k}</dt><dd>${v}</dd>`;
  const hw = i.hardware || {};
  const cpu = i.cpu || {};
  const linkIcon = (t) => t === "wifi" ? icon("wifi", 13) : t === "phys" ? icon("wired", 13) : "";
  const ifRows = (i.interfaces || []).filter((x) => (x.ipv4 || []).length || x.state === "up").map((x) => {
    const w = x.wifi || {};
    return `<tr><td>${linkIcon(x.kind)} <span class="mono">${esc(x.name)}</span></td>
      <td class="mono t2">${(x.ipv4 || []).map(esc).join(", ")}</td>
      <td class="t2">${x.speed ? esc(x.speed) + " Mb/s" : ""}${x.duplex === "half" ? ' <span class="badge crit">half</span>' : ""}${w.signal_dbm != null ? ` ${esc(w.signal_dbm)} dBm` : ""}</td>
      <td class="t2">${(x.rx_errs || 0) + (x.tx_errs || 0) + (x.rx_drop || 0) ? `<span class="badge crit">${(x.rx_errs || 0) + (x.tx_errs || 0) + (x.rx_drop || 0)} err</span>` : "ok"}</td></tr>`;
  }).join("");
  const disks = (i.disks || []).filter((x) => x.size > 0).map((x) =>
    `<tr><td class="mono t2">${esc(x.mount)}</td><td class="t2">${esc(x.fs || "")}</td>
     <td>${meter(x.pct)} ${x.pct != null ? esc(x.pct) + " %" : ""}</td>
     <td class="t2 num">${bytes(x.used)} / ${bytes(x.size)}</td></tr>`).join("");
  return `<div class="card"><div class="card-h"><h2>${icon("key", 16)} Inventaire SSH</h2>
      <span class="sub">collecté ${ago(s.last_success)} · ${s.duration ?? "?"}s</span></div>
    <dl class="kv ssh-kv">
      ${kv("Système", esc(i.os?.name || i.system || ""))}
      ${kv("Noyau", esc(i.kernel || ""))}
      ${kv("Machine", esc([hw.vendor, hw.model].filter(Boolean).join(" ") || i.virtualization || ""))}
      ${kv("Processeur", esc((cpu.model || "") + (cpu.cores ? ` · ${cpu.cores} cœurs` : "")))}
      ${kv("Charge", i.load ? i.load.map((x) => x.toFixed(2)).join(" ") : "")}
      ${kv("Mémoire", mem.total ? `${bytes(memUsed)} / ${bytes(mem.total)} (${memPct} %)` : "")}
      ${kv("Uptime", i.uptime_s ? fmtDur(i.uptime_s) : "")}
      ${kv("Passerelle", esc(i.default_gateway || ""))}
      ${kv("Horloge", i.ntp_synced === false ? '<span class="badge crit">NTP non synchronisé</span>' : (i.clock_skew_s != null && Math.abs(i.clock_skew_s) > 5 ? `décalage ${esc(i.clock_skew_s)}s` : (i.ntp_synced ? "synchronisée" : "")))}
      ${kv("Température", i.temperature_max ? esc(i.temperature_max) + " °C" : "")}
      ${kv("Conteneurs", (i.containers || []).length ? i.containers.length + " actifs" : "")}
    </dl>
    ${ifRows ? `<h3 class="ssh-h">Interfaces</h3><div class="table-wrap"><table class="table-plain"><tbody>${ifRows}</tbody></table></div>` : ""}
    ${disks ? `<h3 class="ssh-h">Disques</h3><div class="table-wrap"><table class="table-plain"><tbody>${disks}</tbody></table></div>` : ""}
    ${(i.containers || []).length ? `<h3 class="ssh-h">Conteneurs</h3><div class="chips">${i.containers.slice(0, 24).map((c) => `<span class="badge" title="${esc(c.image || "")}">${esc(c.name)}</span>`).join(" ")}</div>` : ""}
  </div>`;
}
function meter(pct) {
  if (pct == null) return "";
  const cls = pct >= 90 ? "crit" : pct >= 75 ? "warn" : "ok";
  return `<span class="meter"><span class="meter-b ${cls}" style="width:${Math.min(100, pct)}%"></span></span>`;
}

// ------------------------------------------------------------------ page : latence (heatmap)
async function pageLatency(root) {
  $("#page-title").textContent = "Latence";
  let range = prefs.get("hm-range", "24h");
  let mode = prefs.get("hm-mode", "latency");
  root.innerHTML = `
    <div class="card">
      <div class="card-h"><h2>Heatmap par appareil</h2><span class="sub" id="hm-sub"></span>
        <div class="right">${segHTML("hm-mode", [["latency", "Latence"], ["uptime", "Disponibilité"]], mode)} ${segHTML("hm-range", [["24h", "24 h"], ["7d", "7 j"]], range)}</div></div>
      <div id="hm-scale" style="margin-bottom:10px"></div>
      <div id="hm"></div>
    </div>`;
  const draw = async () => {
    const h = await api(`heatmap?range=${range}`);
    const vals = h.latency.flat().filter((v) => v != null).sort((a, b) => a - b);
    const vmax = vals.length ? vals[Math.floor(vals.length * 0.98)] || vals[vals.length - 1] : 10;
    $("#hm-sub").textContent = `${h.devices.length} appareils · pas de ${h.step / 3600} h`;
    $("#hm-scale").innerHTML = mode === "latency"
      ? `<div class="scale">faible <span class="bar" style="background:linear-gradient(90deg,${cssVar("--seq-0")},${cssVar("--seq-1")})"></span> ${fmtMs(vmax)}+ <span style="margin-left:14px;display:inline-flex;gap:6px;align-items:center"><i style="width:12px;height:12px;border:1.5px solid var(--critical);border-radius:3px"></i>hors ligne</span> <span style="display:inline-flex;gap:6px;align-items:center"><i style="width:12px;height:12px;background:var(--surface-3);border-radius:3px"></i>pas de mesure</span></div>`
      : `<div class="scale">${[[1, "≥ 99 %"], [0.95, "90–99 %"], [0.6, "50–90 %"], [0.1, "< 50 %"], [null, "pas de données"]].map(([v, l]) => `<span style="display:inline-flex;gap:6px;align-items:center"><i style="width:12px;height:12px;border-radius:3px;background:${uptimeColor(v)}"></i>${l}</span>`).join("")}</div>`;
    heatmap($("#hm"), {
      rows: h.devices.map((d) => ({ label: d.name || d.ip, sub: d.ip })),
      t: h.t, values: mode === "latency" ? h.latency : h.up, up: h.up, mode, vmax,
      onRow: (i) => (location.hash = `#/device/${h.devices[i].id}`),
    });
  };
  bindSeg("hm-mode", (k) => { mode = k; prefs.set("hm-mode", k); draw(); });
  bindSeg("hm-range", (k) => { range = k; prefs.set("hm-range", k); draw(); });
  await draw();
  state.refresh = draw;
}

// ------------------------------------------------------------------ page : événements
async function pageEvents(root) {
  $("#page-title").textContent = "Événements";
  let type = "";
  root.innerHTML = `
    <div class="toolbar">${segHTML("ev-type", [["", "Tous"], ["new_device", "Nouveaux"], ["device_offline", "Hors ligne"], ["device_online", "En ligne"], ["port_opened", "Ports"], ["high_latency", "Latence"], ["ip_changed", "IP"]], type)}</div>
    <div class="card" id="ev"></div>`;
  const draw = async () => {
    const ev = await api(`events?limit=300${type ? "&type=" + type : ""}`);
    $("#ev").innerHTML = eventList(ev);
  };
  bindSeg("ev-type", (k) => { type = k; draw(); });
  await draw();
  state.refresh = draw;
}

// ------------------------------------------------------------------ page : scans
async function pageScans(root) {
  $("#page-title").textContent = "Scans";
  root.innerHTML = `<div class="grid kpis" id="sc-kpi"></div>
    <div class="card"><div class="card-h"><h2>Historique</h2><div class="right"><button class="btn" id="sc-deep">${icon("scan", 15)} Scan nmap complet</button></div></div>
    <div class="table-wrap"><table class="table-plain"><thead><tr><th>Type</th><th>Début</th><th>Durée</th><th>Hôtes</th><th>Détail</th></tr></thead><tbody id="sc"></tbody></table></div></div>`;
  const draw = async () => {
    const [scans] = await Promise.all([api("scans"), loadOverview()]);
    const o = state.overview;
    const st = o.status;
    $("#sc-kpi").innerHTML = `
      <div class="card kpi"><div class="label">Découverte (ARP + ICMP)</div><div class="value">${st.discovery.duration ?? "—"}<small>s</small></div><div class="foot">dernière ${ago(st.discovery.last)} · prochaine ${ago(st.discovery.next)}</div></div>
      <div class="card kpi"><div class="label">Scan nmap</div><div class="value">${st.deep.running}<small>en cours</small></div><div class="foot">${st.deep.queued} en file · prochain ${ago(st.deep.next)}</div></div>
      <div class="card kpi"><div class="label">Réseau scanné</div><div class="value" style="font-size:20px">${esc(o.network.subnet || "?")}</div><div class="foot">interface ${esc(o.network.interface)} · passerelle ${esc(o.network.gateway || "?")}${(o.network.excluded || []).length ? ` · exclus : ${o.network.excluded.map(esc).join(", ")}` : ""}</div></div>`;
    const label = { discovery: "Découverte", deep: "nmap planifié", "deep-manual": "nmap manuel" };
    $("#sc").innerHTML = scans.map((s) => `<tr>
      <td>${label[s.type] || esc(s.type)}</td>
      <td class="t2">${fmtDateTime(s.started)}</td>
      <td class="num">${s.finished ? (s.detail?.duration ?? s.finished - s.started) + " s" : '<span class="badge watch">en cours</span>'}</td>
      <td class="num">${s.hosts ?? "—"}</td>
      <td class="t2">${s.detail?.new ? `${s.detail.new} nouveau(x)` : ""}${s.detail?.open_ports != null ? `${s.detail.open_ports} port(s) ouvert(s)` : ""}</td>
    </tr>`).join("");
  };
  $("#sc-deep").addEventListener("click", async (e) => {
    e.currentTarget.disabled = true;
    const r = await api("scan/deep", { method: "POST" });
    toast(r.queued ? `Scan nmap lancé sur ${r.hosts} appareil(s)` : "Scan déjà en file d'attente");
    draw();
  });
  await draw();
  state.refresh = draw;
}

// ------------------------------------------------------------------ page : diagnostic
const ORIGIN_LABEL = {
  wan: "Internet / FAI", gateway: "Box / routeur", lan: "Réseau local", wifi: "Wi-Fi",
  device: "Appareils", dns: "DNS", bufferbloat: "Saturation (bufferbloat)", mtu: "MTU", scanner: "Machine NetWatch",
  security: "Sécurité",
};
function findingCard(f) {
  return `<div class="finding sev-${f.severity}">
    <div class="finding-h">${sevIcon(f.severity)}<b>${esc(f.title)}</b>
      <span class="badge">${esc(ORIGIN_LABEL[f.category] || f.category)}</span></div>
    ${f.detail ? `<div class="finding-d">${esc(f.detail)}</div>` : ""}
    ${f.suggestion ? `<div class="finding-s">${icon("info", 13)} ${esc(f.suggestion)}</div>` : ""}
  </div>`;
}

async function pageDiagnostic(root) {
  $("#page-title").textContent = "Diagnostic";
  root.innerHTML = `
    <div class="toolbar">
      <button class="btn primary" id="run-diag">${icon("diag", 15)} Lancer un diagnostic complet</button>
      <span class="muted" id="diag-state" style="font-size:12.5px"></span>
    </div>
    <div id="verdict"></div>
    <div id="conflicts"></div>
    <div class="card"><div class="card-h"><h2>Constats actifs</h2><span class="sub" id="find-sub"></span></div>
      <div id="findings"></div></div>
    <div class="card" style="margin-top:16px"><div class="card-h"><h2>Historique des diagnostics</h2></div>
      <div class="table-wrap"><table class="table-plain"><thead><tr><th>Début</th><th>Déclencheur</th><th>Verdict</th></tr></thead>
      <tbody id="runs"></tbody></table></div></div>`;

  const TRIG = { scheduled: "planifié", manual: "manuel", anomaly: "anomalie" };
  const draw = async () => {
    const [findings, conflicts, runs, o] = await Promise.all([
      api("findings"), api("conflicts"), api("diagnostics"), api("overview"),
    ]);
    // verdict = dernier run
    let verdict = null;
    if (runs[0]) {
      try { verdict = (await api(`diagnostics/${runs[0].id}`)).result?.verdict; } catch { /* ignore */ }
    }
    $("#verdict").innerHTML = verdict ? `
      <div class="card verdict sev-${verdict.severity}">
        <div class="verdict-h">${icon("diag", 20)}<div><b>Origine la plus probable</b>
          <div class="verdict-o">${esc(verdict.origin_label || verdict.summary)}</div></div></div>
        <div class="verdict-s">${esc(verdict.summary)}</div>
      </div>` : `<div class="card empty">Aucun diagnostic n'a encore été exécuté.</div>`;

    const open = conflicts.filter((c) => !c.resolved);
    $("#conflicts").innerHTML = open.length ? `<div class="card sev-critical" style="margin-bottom:16px">
      <div class="card-h"><h2>${icon("conflict", 16)} Conflits d'adresse IP</h2></div>
      ${open.map((c) => `<div class="finding sev-critical"><div class="finding-h">
        <b class="mono">${esc(c.ip)}</b> revendiquée par ${c.macs.length} MAC</div>
        <div class="finding-d mono">${c.macs.map(esc).join(" · ")}</div>
        <div class="finding-s">${icon("info", 13)} ${c.source === "arp_multi"
          ? "Plusieurs appareils répondent pour cette IP. Vérifiez les IP fixes en double ou une usurpation ARP."
          : "Cette IP change de MAC de façon répétée : bail DHCP en collision ou IP fixe dans la plage DHCP."}</div>
      </div>`).join("")}</div>` : "";

    const active = findings.filter((f) => f.active);
    $("#find-sub").textContent = active.length ? `${active.length} constat(s)` : "";
    const order = { critical: 0, warning: 1, info: 2 };
    active.sort((a, b) => order[a.severity] - order[b.severity]);
    $("#findings").innerHTML = active.length
      ? active.map(findingCard).join("")
      : `<div class="empty">Aucun problème détecté au dernier diagnostic. ${icon("info", 14)}</div>`;

    $("#runs").innerHTML = runs.map((r) => `<tr data-href="#/diagnostic" style="cursor:pointer">
      <td class="t2">${fmtDateTime(r.started)}</td>
      <td>${esc(TRIG[r.trigger] || r.trigger)}</td>
      <td>${esc(r.summary || (r.finished ? "—" : "en cours…"))}</td></tr>`).join("")
      || `<tr><td colspan="3" class="empty">—</td></tr>`;
    $("#diag-state").textContent = o.diag?.running ? "Diagnostic en cours…" : "";
    $("#run-diag").disabled = !!o.diag?.running;
  };

  $("#run-diag").addEventListener("click", async (e) => {
    e.target.disabled = true;
    const r = await api("diagnostics", { method: "POST", body: {} });
    toast(r.started ? "Diagnostic lancé — résultats dans quelques secondes" : (r.reason || r.error || "Impossible"));
    setTimeout(draw, 1500);
  });
  await draw();
  state.refresh = draw;
}

// ------------------------------------------------------------------ page : identifiants SSH
async function pageCredentials(root) {
  $("#page-title").textContent = "Identifiants SSH";
  const data = await api("credentials");
  const blank = { name: "", username: "", auth_type: "password", port: 22, scope: [], priority: 100, use_sudo: false, enabled: true };

  const form = (c, isNew) => `
    <div class="card cred-form" data-id="${c.id ?? ""}">
      <div class="grid cols-2">
        <div class="form-row"><span>Nom</span><input class="f-name" value="${esc(c.name)}" placeholder="ex. root Debian"></div>
        <div class="form-row"><span>Utilisateur</span><input class="f-user" value="${esc(c.username)}" placeholder="root"></div>
        <div class="form-row"><span>Type</span><select class="f-auth">
          <option value="password" ${c.auth_type === "password" ? "selected" : ""}>Mot de passe</option>
          <option value="key" ${c.auth_type === "key" ? "selected" : ""}>Clé privée</option></select></div>
        <div class="form-row"><span>Port</span><input class="f-port" type="number" value="${c.port || 22}"></div>
        <div class="form-row"><span>Portée (CIDR, vide = tout)</span><input class="f-scope" value="${esc((c.scope || []).join(", "))}" placeholder="192.168.1.0/24"></div>
        <div class="form-row"><span>Priorité (plus petit = essayé d'abord)</span><input class="f-prio" type="number" value="${c.priority ?? 100}"></div>
      </div>
      <div class="form-row"><span>${c.auth_type === "key" ? "Clé privée" : "Mot de passe"}${isNew ? "" : " (laisser vide = inchangé)"}</span>
        <textarea class="f-secret" placeholder="${c.auth_type === "key" ? "-----BEGIN OPENSSH PRIVATE KEY-----" : "••••••••"}" ${c.auth_type === "key" ? 'style="min-height:110px;font-family:var(--mono)"' : ""}></textarea></div>
      <div class="form-row f-pass-row" ${c.auth_type === "key" ? "" : 'style="display:none"'}><span>Passphrase de la clé (optionnel)</span><input class="f-pass" type="password" placeholder="${c.has_passphrase ? "définie — laisser vide = inchangée" : ""}"></div>
      <div style="display:flex;gap:18px;flex-wrap:wrap;margin:6px 0 12px">
        <label class="check"><span class="switch"><input type="checkbox" class="f-sudo" ${c.use_sudo ? "checked" : ""}><span></span></span>Utiliser sudo -n (dmidecode…)</label>
        <label class="check"><span class="switch"><input type="checkbox" class="f-enabled" ${c.enabled ? "checked" : ""}><span></span></span>Actif</label>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <button class="btn primary f-save">${isNew ? "Ajouter" : "Enregistrer"}</button>
        ${isNew ? "" : `<button class="btn f-test">Tester sur une IP…</button><button class="btn danger f-del">Supprimer</button>`}
        <span class="f-msg muted" style="font-size:12.5px"></span>
      </div>
    </div>`;

  const stats = (c) => c.success_count || c.failure_count
    ? `<span class="muted" style="font-size:12px">${c.success_count} ✓ / ${c.failure_count} ✗${c.last_success ? " · dernier succès " + ago(c.last_success) : ""}</span>` : "";

  root.innerHTML = `
    ${data.locked ? `<div class="banner sev-critical">${icon("warn", 15)} Coffre verrouillé : ${esc(data.reason || "")}. Les identifiants ne peuvent pas être utilisés. Vérifiez <span class="mono">NETWATCH_SECRET_KEY</span>.</div>` : ""}
    ${!data.available && !data.locked ? `<div class="banner">${icon("info", 15)} L'inventaire SSH est indisponible (module asyncssh absent ou SSH désactivé).</div>` : ""}
    <p class="muted" style="font-size:13px">Les secrets sont chiffrés au repos et ne ressortent jamais par l'API. Un jeu d'identifiants n'est essayé que sur les sous-réseaux de sa portée et sur les hôtes dont le port SSH est ouvert.</p>
    <div id="cred-list"></div>
    <div class="card-h" style="margin-top:18px"><h2>Ajouter un jeu d'identifiants</h2></div>
    <div id="cred-new"></div>`;

  const bindForm = (el, isNew) => {
    const g = (s) => el.querySelector(s);
    const msg = (t, err) => { const m = g(".f-msg"); m.textContent = t; m.className = "f-msg " + (err ? "danger" : "muted"); };
    g(".f-auth").addEventListener("change", (e) => {
      g(".f-pass-row").style.display = e.target.value === "key" ? "" : "none";
    });
    const collect = () => ({
      name: g(".f-name").value, username: g(".f-user").value, auth_type: g(".f-auth").value,
      port: +g(".f-port").value || 22, scope: g(".f-scope").value, priority: +g(".f-prio").value || 100,
      use_sudo: g(".f-sudo").checked, enabled: g(".f-enabled").checked,
      secret: g(".f-secret").value || undefined, passphrase: g(".f-pass")?.value || undefined,
    });
    g(".f-save").addEventListener("click", async () => {
      try {
        const id = el.dataset.id;
        if (isNew) await api("credentials", { method: "POST", body: collect() });
        else await api(`credentials/${id}`, { method: "PATCH", body: collect() });
        toast(isNew ? "Identifiant ajouté" : "Identifiant enregistré");
        pageCredentials(root);
        loadOverview();
      } catch (e) { msg(e.message.replace(/^\d+ /, ""), true); }
    });
    g(".f-del")?.addEventListener("click", async () => {
      await api(`credentials/${el.dataset.id}`, { method: "DELETE" });
      toast("Identifiant supprimé");
      pageCredentials(root);
    });
    g(".f-test")?.addEventListener("click", async () => {
      const ip = prompt("Adresse IP à tester avec cet identifiant :");
      if (!ip) return;
      msg("Test en cours…");
      const r = await api(`credentials/${el.dataset.id}/test`, { method: "POST", body: { ip } });
      msg(r.ok ? `✓ Connexion réussie (${r.hostname || "hôte"}, ${r.duration}s)` : `✗ ${r.error || r.kind}`, !r.ok);
    });
  };

  $("#cred-list").innerHTML = data.credentials.length
    ? data.credentials.map((c) => `
      <div class="card cred-row ${c.enabled ? "" : "off"}">
        <div class="cred-head"><b>${esc(c.name)}</b> <span class="mono t2">${esc(c.username)}@:${c.port}</span>
          <span class="badge">${c.auth_type === "key" ? "clé" : "mot de passe"}</span>
          ${(c.scope || []).length ? `<span class="badge mono">${c.scope.map(esc).join(", ")}</span>` : '<span class="badge">tout le réseau</span>'}
          ${c.enabled ? "" : '<span class="badge">inactif</span>'}
          <div class="spacer" style="flex:1"></div>${stats(c)}
          <button class="btn edit" data-id="${c.id}">Modifier</button></div>
        <div class="cred-edit" id="edit-${c.id}" style="display:none"></div>
      </div>`).join("")
    : `<div class="empty">Aucun identifiant. Ajoutez-en un ci-dessous pour activer l'inventaire SSH.</div>`;

  $("#cred-list").querySelectorAll(".edit").forEach((b) => b.addEventListener("click", () => {
    const c = data.credentials.find((x) => x.id == b.dataset.id);
    const box = $(`#edit-${c.id}`);
    if (box.style.display === "none") {
      box.innerHTML = form(c, false);
      box.style.display = "";
      bindForm(box.querySelector(".cred-form"), false);
    } else { box.style.display = "none"; box.innerHTML = ""; }
  }));

  $("#cred-new").innerHTML = form(blank, true);
  bindForm($("#cred-new").querySelector(".cred-form"), true);
  state.refresh = null;
}

// ------------------------------------------------------------------ page : notifications push
function urlB64ToUint8(base64) {
  const pad = "=".repeat((4 - (base64.length % 4)) % 4);
  const b64 = (base64 + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64);
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}
const pushSupported = () => "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;

async function pageNotifications(root) {
  $("#page-title").textContent = "Notifications";
  const cfg = await api("push/config");

  if (!cfg.available) {
    root.innerHTML = `<div class="card empty">Les notifications push ne sont pas disponibles côté serveur (module manquant).</div>`;
    return;
  }
  if (!pushSupported()) {
    root.innerHTML = `<div class="banner">${icon("info", 15)} Ce navigateur ne gère pas les notifications push. Sur iPhone/iPad, ajoute d'abord NetWatch à l'écran d'accueil (Partager → Sur l'écran d'accueil), puis rouvre-le depuis l'icône.</div>`;
    return;
  }

  let reg = await navigator.serviceWorker.getRegistration();
  if (!reg) { try { reg = await navigator.serviceWorker.register("/sw.js"); } catch { /* ignore */ } }
  if (!reg) {
    root.innerHTML = `<div class="banner">${icon("info", 15)} Le service worker n'est pas actif dans ce navigateur : les notifications ne peuvent pas être activées ici. Sur mobile, installe NetWatch sur l'écran d'accueil puis rouvre-le.</div>`;
    return;
  }
  let sub = null;
  try { sub = await reg.pushManager.getSubscription(); } catch { /* ignore */ }
  const tail = (s) => (s ? s.endpoint.slice(-12) : null);
  let server = sub ? cfg.subscriptions.find((x) => x.endpoint_tail === tail(sub)) : null;
  let types = new Set(server ? server.notify_types : cfg.event_types.filter((e) => e.default).map((e) => e.key));

  const render = () => {
    const active = !!sub && !!server;
    root.innerHTML = `
      <div class="card">
        <div class="card-h"><h2>${icon("push", 16)} Cet appareil</h2>
          <div class="right"><span class="status ${active ? "on" : "off"}"><i></i>${active ? "Notifications activées" : "Désactivées"}</span></div></div>
        <p class="muted" style="font-size:13px;margin:2px 0 12px">Les notifications sont envoyées même quand l'app est fermée. Chaque appareil choisit les alertes qu'il reçoit.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${active
            ? `<button class="btn" id="p-test">Envoyer un test</button><button class="btn danger" id="p-off">Désactiver sur cet appareil</button>`
            : `<button class="btn primary" id="p-on">${icon("push", 15)} Activer les notifications</button>`}
          <span class="muted" id="p-msg" style="font-size:12.5px;align-self:center"></span>
        </div>
      </div>
      ${active ? `<div class="card" style="margin-top:16px">
        <div class="card-h"><h2>Alertes à recevoir</h2><span class="sub">sur cet appareil</span></div>
        <div class="notif-types">${cfg.event_types.map((e) => `
          <label class="check"><span class="switch"><input type="checkbox" data-k="${e.key}" ${types.has(e.key) ? "checked" : ""}><span></span></span>${esc(e.label)}</label>`).join("")}</div>
      </div>` : ""}
      ${cfg.subscriptions.length ? `<div class="card" style="margin-top:16px">
        <div class="card-h"><h2>Appareils abonnés</h2><span class="sub">${cfg.subscriptions.length}</span></div>
        <div class="table-wrap"><table class="table-plain"><tbody>${cfg.subscriptions.map((s) => `
          <tr><td>${icon("push", 15)} ${esc(s.label || "Appareil")} ${s.endpoint_tail === tail(sub) ? '<span class="badge watch">celui-ci</span>' : ""}</td>
            <td class="t2">${s.notify_types.length} alerte(s)</td>
            <td class="t2">${s.last_ok ? "vu " + ago(s.last_ok) : (s.last_error ? '<span class="badge crit">erreur</span>' : "—")}</td>
            <td style="text-align:right"><button class="btn danger p-del" data-e="${esc(s.endpoint_tail)}">Retirer</button></td></tr>`).join("")}</tbody></table></div>
      </div>` : ""}`;

    const msg = (t) => { const m = $("#p-msg"); if (m) m.textContent = t; };

    $("#p-on")?.addEventListener("click", async () => {
      msg("Autorisation…");
      const perm = await Notification.requestPermission();
      if (perm !== "granted") { msg("Permission refusée dans le navigateur."); return; }
      try {
        sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlB64ToUint8(cfg.vapid_public_key) });
        server = await api("push/subscribe", { method: "POST", body: { subscription: sub.toJSON(), notify_types: [...types] } });
        cfg.subscriptions = (await api("push/config")).subscriptions;
        toast("Notifications activées sur cet appareil");
        render();
      } catch (e) { msg("Échec : " + e.message); }
    });
    $("#p-off")?.addEventListener("click", async () => {
      const ep = sub?.endpoint;
      try { await sub?.unsubscribe(); } catch { /* ignore */ }
      if (ep) await api("push/unsubscribe", { method: "POST", body: { endpoint: ep } });
      sub = null; server = null;
      cfg.subscriptions = (await api("push/config")).subscriptions;
      toast("Notifications désactivées");
      render();
    });
    $("#p-test")?.addEventListener("click", async () => {
      msg("Envoi…");
      const r = await api("push/test", { method: "POST", body: { endpoint: sub.endpoint } });
      msg(r.ok ? "Test envoyé ✓ (regarde tes notifications)" : "Échec de l'envoi.");
    });
    root.querySelectorAll(".notif-types input").forEach((c) => c.addEventListener("change", async () => {
      c.checked ? types.add(c.dataset.k) : types.delete(c.dataset.k);
      await api("push/subscribe", { method: "PATCH", body: { endpoint: sub.endpoint, notify_types: [...types] } });
    }));
    root.querySelectorAll(".p-del").forEach((b) => b.addEventListener("click", async () => {
      const s = cfg.subscriptions.find((x) => x.endpoint_tail === b.dataset.e);
      if (s && s.endpoint_tail === tail(sub)) { try { await sub.unsubscribe(); } catch { /* ignore */ } sub = null; server = null; }
      // suppression côté serveur par tail : on renvoie l'endpoint courant si c'est le même, sinon on recharge
      await api("push/unsubscribe", { method: "POST", body: { endpoint: s && s.endpoint_tail === tail(sub) ? sub?.endpoint : undefined, endpoint_tail: b.dataset.e } });
      cfg.subscriptions = (await api("push/config")).subscriptions;
      render();
    }));
  };
  render();
  state.refresh = null;
}

// ------------------------------------------------------------------ page : réglages
async function pageSettings(root) {
  $("#page-title").textContent = "Réglages";
  const data = await api("settings");
  const field = (s) => {
    const id = `set-${s.key}`;
    if (s.type === "bool") {
      return `<label class="check"><span class="switch"><input type="checkbox" id="${id}" data-k="${s.key}" data-t="bool" ${s.value ? "checked" : ""}><span></span></span>${esc(s.label)}</label>`;
    }
    const val = s.type === "csv" ? (s.value || []).join(", ") : (s.value ?? "");
    const inputType = (s.type === "int" || s.type === "float") ? "number" : "text";
    const step = s.type === "float" ? ' step="any"' : "";
    return `<div class="set-row"><label for="${id}">${esc(s.label)}${s.restart ? ' <span class="badge">redémarrage</span>' : ""}
        ${s.help ? `<span class="set-help">${esc(s.help)}</span>` : ""}</label>
      <input id="${id}" data-k="${s.key}" data-t="${s.type}" type="${inputType}"${step} value="${esc(val)}"></div>`;
  };
  root.innerHTML = `
    <div style="margin-bottom:12px"><button class="btn" id="set-wizard">Relancer l'assistant de configuration</button></div>
    <p class="muted" style="font-size:13px">Les changements s'appliquent au cycle suivant (sauf mention « redémarrage »). Les secrets (mots de passe, identifiants) se gèrent ailleurs.</p>
    ${data.groups.map((g) => `<div class="card" style="margin-bottom:16px">
      <div class="card-h"><h2>${esc(g.name)}</h2></div>
      <div class="settings-grid">${g.settings.map(field).join("")}</div></div>`).join("")}
    <div style="display:flex;gap:10px;align-items:center;position:sticky;bottom:0;padding:12px 0;background:linear-gradient(transparent,var(--page) 40%)">
      <button class="btn primary" id="set-save">Enregistrer</button>
      <button class="btn" id="set-reload">Annuler</button>
      <span id="set-msg" class="muted" style="font-size:13px"></span>
    </div>`;

  $("#set-reload").addEventListener("click", () => pageSettings(root));
  $("#set-wizard").addEventListener("click", async () => { await api("wizard/reset", { method: "POST" }); showWizard(); });
  $("#set-save").addEventListener("click", async () => {
    const body = {};
    root.querySelectorAll("[data-k]").forEach((el) => {
      const t = el.dataset.t;
      body[el.dataset.k] = t === "bool" ? el.checked : el.value;
    });
    try {
      const r = await api("settings", { method: "PATCH", body });
      const n = Object.keys(r.applied).length;
      const errs = Object.keys(r.errors || {});
      let msg = `${n} réglage(s) enregistré(s).`;
      if (r.restart_needed?.length) msg += ` Redémarrage requis pour : ${r.restart_needed.join(", ")}.`;
      if (errs.length) msg += ` Erreurs : ${errs.join(", ")}.`;
      $("#set-msg").textContent = msg;
      toast("Réglages enregistrés");
      loadOverview();
    } catch (e) { $("#set-msg").textContent = "Échec : " + e.message; }
  });
  state.refresh = null;
}

// ------------------------------------------------------------------ page : box Internet
const mbps = (kbps) => (kbps == null ? "—" : kbps >= 1000 ? `${(kbps / 1000).toFixed(kbps >= 10000 ? 0 : 1)} Mb/s` : `${kbps} kb/s`);

// Choix du fournisseur et accès à la box : partagé entre la page Box et l'assistant de configuration.
function boxAccess(el, b, onUpdate) {
  const p = b.provider;
  const det = (b.detected || [])[0];
  const msg = (t) => { const m = $("#bx-msg", el); if (m) m.textContent = t; };
  const provOpts = (b.providers || []).map((x) =>
    `<option value="${esc(x.id)}" ${p && x.id === p.id ? "selected" : ""}>${esc(x.label)}</option>`).join("");
  let creds = "";
  if (p?.auth === "approval") {
    creds = `<p class="muted" style="font-size:12.5px;margin:0 0 8px">${esc(p.hint)}</p>
      ${b.has_token
        ? `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><span class="badge good">NetWatch est autorisé sur la box</span>
            <button class="btn" type="button" id="bx-del">Retirer l'autorisation</button></div>`
        : `<button class="btn primary" type="button" id="bx-approve">Demander l'autorisation</button>`}`;
  } else if (p) {
    creds = `<p class="muted" style="font-size:12.5px;margin:0 0 8px">${esc(p.hint)} Il est chiffré et ne ressort jamais de NetWatch.</p>
      ${p.auth === "userpass" ? `<input id="bx-user" autocomplete="off" placeholder="Identifiant" value="${esc(b.username || p.default_user)}" style="width:100%;margin-bottom:8px">` : ""}
      <input id="bx-pw" type="password" autocomplete="off" placeholder="${b.has_password ? "•••••••• (enregistré)" : "Mot de passe de la box"}" style="width:100%;margin-bottom:10px">
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn primary" type="button" id="bx-save">Enregistrer</button>
        <button class="btn" type="button" id="bx-test">Tester</button>
        ${b.has_password ? `<button class="btn" type="button" id="bx-del">Supprimer</button>` : ""}
      </div>`;
  }
  el.innerHTML = `
    ${b.vault_locked ? `<div class="banner">Coffre verrouillé : impossible d'enregistrer des identifiants.</div>` : ""}
    ${b.auth_failed ? `<div class="banner sev-critical">La box a refusé les identifiants enregistrés. Saisissez-les à nouveau.</div>` : ""}
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:6px">
      <select id="bx-prov" style="flex:1;min-width:180px"><option value="">— choisir mon fournisseur —</option>${provOpts}</select>
      <button class="btn" type="button" id="bx-detect">${icon("radar", 14)} Détecter</button>
    </div>
    <div class="muted" style="font-size:12.5px;margin-bottom:10px">${det
      ? `Détecté à ${esc(b.host)} : ${esc(det.label)}${det.model ? " · " + esc(det.model) : ""}`
      : b.detected ? `Aucune box reconnue à ${esc(b.host || "?")} : choisissez le fournisseur.` : `Adresse utilisée : ${esc(b.host || "passerelle")}`}</div>
    ${p?.experimental ? `<div class="banner" style="font-size:12.5px">Ce fournisseur n'a pas encore été vérifié sur une vraie box. Si une information manque, la raison s'affiche sous « Lectures refusées ».</div>` : ""}
    ${creds}
    <div class="muted" id="bx-msg" style="font-size:12.5px;margin-top:8px"></div>
    ${Object.keys(b.endpoints || {}).length ? `<details style="margin-top:8px;font-size:12.5px"><summary>Lectures refusées (${Object.keys(b.endpoints).length})</summary>
      ${Object.entries(b.endpoints).map(([k, v]) => `<div class="muted"><span class="mono">${esc(k)}</span> : ${esc(v)}</div>`).join("")}</details>` : ""}`;

  $("#bx-prov", el).addEventListener("change", async (e) => {
    try { onUpdate(await api("box/provider", { method: "PUT", body: { provider: e.target.value } })); }
    catch (err) { msg("Échec : " + err.message); }
  });
  $("#bx-detect", el).addEventListener("click", async () => {
    msg("Détection en cours…");
    try {
      let r = await api("box/detect", { method: "POST" });
      if (r.detected?.length === 1) r = await api("box/provider", { method: "PUT", body: { provider: r.detected[0].provider } });
      onUpdate(r);
    } catch (err) { msg("Échec : " + err.message); }
  });
  const cred = () => ({ password: $("#bx-pw", el)?.value || "", username: $("#bx-user", el)?.value });
  $("#bx-save", el)?.addEventListener("click", async () => {
    const c = cred();
    if (!c.password) return msg("Saisissez le mot de passe.");
    try {
      const nb = await api("box/credentials", { method: "PUT", body: c });
      onUpdate(nb);
    } catch (err) { msg("Échec : " + err.message); }
  });
  $("#bx-test", el)?.addEventListener("click", async () => {
    msg("Test en cours…");
    try {
      const r = await api("box/test", { method: "POST", body: cred() });
      if (!r.ok) return msg("Échec : " + r.error);
      msg(r.authenticated ? `Connexion réussie${r.model ? " (" + r.model + ")" : ""} : ${r.hosts} appareil(s) listé(s).`
        : `Box joignable${r.model ? " (" + r.model + ")" : ""}, mais aucun identifiant à tester.`);
    } catch (err) { msg("Échec : " + err.message); }
  });
  $("#bx-del", el)?.addEventListener("click", async () => {
    if (!confirm("Supprimer les identifiants enregistrés ?")) return;
    onUpdate(await api("box/credentials", { method: "DELETE" }));
  });
  $("#bx-approve", el)?.addEventListener("click", async () => {
    boxAccess.busy = true;
    try {
      const r = await api("box/approval", { method: "POST" });
      msg(r.message);
      for (let i = 0; i < 45; i++) {
        await new Promise((ok) => setTimeout(ok, 2000));
        if (!el.isConnected) return;
        const s = await api("box/approval");
        if (s.status === "granted") { onUpdate(s.box); return; }
        if (["denied", "timeout", "unknown"].includes(s.status)) return msg("Autorisation refusée ou expirée : réessayez.");
      }
      msg("Pas de réponse : appuyez sur la flèche de la façade, puis réessayez.");
    } catch (err) { msg("Échec : " + err.message); } finally { boxAccess.busy = false; }
  });
}

async function pageBox(root) {
  $("#page-title").textContent = "Box Internet";
  let range = prefs.get("bbox-range", "24h");
  let b = await api("box");

  const draw = () => {
    const s = b.stats, d = b.device || {}, w = b.wan || {};
    const up = b.summary?.internet_up === true;
    const hosts = b.hosts;
    root.innerHTML = `
      ${!b.enabled ? `<div class="banner">La supervision de la box est désactivée. <button class="btn" id="bb-enable">Activer</button></div>` : ""}
      ${b.needs_approval ? `<div class="banner">La box attend votre autorisation : cliquez sur « Demander l'autorisation » ci-dessous.</div>` : ""}
      ${b.error ? `<div class="banner sev-critical">Box injoignable (${esc(b.host)}) : ${esc(b.error)}</div>` : ""}
      <div class="grid kpis">
        <div class="card kpi ${b.summary && b.summary.internet_up === false ? "alert" : ""}"><div class="label">${icon("globe", 15)} Internet</div>
          <div class="value">${b.summary?.internet_up == null ? "—" : up ? "Connecté" : "Coupé"}</div>
          <div class="foot">${esc(w.ip || "")}${w.ip6 ? " · IPv6" : ""}</div></div>
        <div class="card kpi"><div class="label">${icon("router", 15)} ${esc(d.model || b.provider?.label || "Box")}</div>
          <div class="value" style="font-size:20px">${d.uptime != null ? fmtDur(d.uptime) : "—"}</div>
          <div class="foot">${d.firmware ? "firmware " + esc(d.firmware) : ""}${d.ftth ? " · fibre" : ""}</div></div>
        <div class="card kpi"><div class="label">Descendant</div>
          <div class="value" style="font-size:22px">${mbps(s?.rx_kbps)}</div>
          <div class="foot">${s?.rx_contract_kbps ? `sur ${mbps(s.rx_contract_kbps)}` : ""}</div></div>
        <div class="card kpi"><div class="label">Montant</div>
          <div class="value" style="font-size:22px">${mbps(s?.tx_kbps)}</div>
          <div class="foot">${s?.tx_contract_kbps ? `sur ${mbps(s.tx_contract_kbps)}` : ""}</div></div>
        <div class="card kpi"><div class="label">Volume (<span id="bb-vol-range"></span>)</div>
          <div class="value" style="font-size:20px" id="bb-vol">—</div><div class="foot" id="bb-vol-foot"></div></div>
      </div>
      <div class="grid cols-3-1" style="margin-bottom:16px">
        <div class="card"><div class="card-h"><h2>Débit de la ligne</h2><div class="right">${segHTML("r-bbox", RANGES, range)}</div></div>
          <div id="ch-bbox"></div><div class="muted" style="font-size:12px;padding:6px 0 0">Relevé toutes les ${b.interval} s${b.last_poll ? " · dernier " + ago(b.last_poll) : ""}.
            ${b.provider && !(b.provider.features || []).includes("stats") ? " Cette box ne fournit pas le débit de la ligne." : ""}</div></div>
        <div class="card"><div class="card-h"><h2>Accès à la box</h2>
            <div class="right"><button class="btn" id="bb-refresh" title="Interroger la box maintenant">${icon("refresh", 14)}</button></div></div>
          <div id="bx-access"></div>
        </div>
      </div>
      <div class="card"><div class="card-h"><h2>Appareils vus par la box</h2><span class="sub">${hosts ? `${hosts.filter((h) => h.active).length} actif(s) sur ${hosts.length}` : ""}</span></div>
        ${hosts ? `<div class="table-wrap"><table class="table-plain"><thead><tr><th>Nom</th><th>IP</th><th>Point d'accès</th><th>Liaison</th><th>Signal</th><th>État</th><th>NetWatch</th></tr></thead><tbody>
          ${hosts.map((h) => `<tr>
            <td>${esc(h.netwatch_name || h.hostname || h.mac || "—")}</td>
            <td class="mono">${esc(h.ip || "—")}</td>
            <td>${h.ap_kind === "repeater" ? `<span class="badge watch">${esc(h.ap)}</span>` : esc(h.ap || "—")}</td>
            <td>${esc(h.link || "—")}${h.ssid ? ` · ${esc(h.ssid)}` : ""}${h.port && !h.wifi ? ` (port ${esc(h.port)})` : ""}</td>
            <td>${h.rssi != null ? `${esc(h.rssi)} dBm` : "—"}</td>
            <td>${h.active ? '<span class="badge good">actif</span>' : '<span class="badge">inactif</span>'}</td>
            <td>${h.netwatch_id ? `<a href="#/device/${h.netwatch_id}">Voir</a>` : (h.active ? '<span class="badge new">non vu</span>' : "—")}</td></tr>`).join("")}
          </tbody></table></div>`
          : `<div class="empty" style="padding:16px">${b.has_credentials ? "Liste indisponible pour le moment." : "Enregistrez les identifiants de la box pour voir ses appareils connectés."}</div>`}
      </div>`;
    boxAccess($("#bx-access"), b, (nb) => { b = nb; draw(); });
    bind();
    drawUsage();
  };

  const drawUsage = async () => {
    if (!$("#ch-bbox")) return;
    const u = await api(`box/usage?range=${range}`);
    const label = (RANGES.find((r) => r[0] === range) || [0, range])[1];
    $("#bb-vol-range").textContent = label;
    $("#bb-vol").textContent = `↓ ${bytes(u.rx_bytes)}`;
    $("#bb-vol-foot").textContent = `↑ ${bytes(u.tx_bytes)}`;
    if (!u.series.length) { $("#ch-bbox").innerHTML = `<div class="empty" style="padding:24px">Pas encore de relevé.</div>`; return; }
    lineChart($("#ch-bbox"), {
      t: u.series.map((p) => p.ts), height: 230, yFmt: mbps, tipFmt: mbps, label: "Débit de la ligne",
      series: [
        { name: "Descendant", values: u.series.map((p) => p.rx_kbps), color: "--s1", area: true },
        { name: "Montant", values: u.series.map((p) => p.tx_kbps), color: "--s2" },
      ],
    });
  };

  const bind = () => {
    $("#bb-enable")?.addEventListener("click", async () => {
      await api("settings", { method: "PATCH", body: { box_enabled: true } });
      try { b = await api("box/refresh", { method: "POST" }); } catch { b = await api("box"); }
      draw();
    });
    bindSeg("r-bbox", (k) => { range = k; prefs.set("bbox-range", k); drawUsage(); });
    $("#bb-refresh").addEventListener("click", async () => {
      try { b = await api("box/refresh", { method: "POST" }); draw(); } catch (e) { toast("Échec : " + esc(e.message)); }
    });
  };

  draw();
  state.refresh = async () => {
    b = await api("box");
    if (!boxAccess.busy && !document.activeElement?.closest?.("#bx-access")) draw();
  };
}

// ------------------------------------------------------------------ page : Zigbee (Zigbee2MQTT)
const Z_RANGES = [["6h", "6 h"], ["24h", "24 h"], ["7d", "7 j"]];
const Z_HOURS = { "6h": 6, "24h": 24, "7d": 168 };
const Z_TYPE = { Router: "Routeur", EndDevice: "Terminal", Coordinator: "Coordinateur" };
const Z_CAUSE = { bridge: "Zigbee2MQTT arrêté", global: "Tout le réseau", group: "Groupe d'appareils" };
const Z_LOG = { device_leave: "a quitté le réseau", device_joined: "a rejoint le réseau", device_announce: "s'est ré-annoncé", device_interview: "interview" };
const lqiColor = (v) => (v == null ? "" : `color:var(${v < 50 ? "--critical-text" : v < 100 ? "--warning" : "--good-text"})`);
const zBad = (d) => d.drops > 0 || d.online === false || d.errors.total > 0 || (d.lqi_avg != null && d.lqi_avg < 50);

function zTestMessage(r) {
  if (!r.ok) return "Échec : " + r.error;
  if (r.warning) return r.warning;
  return `Connexion réussie : Zigbee2MQTT ${r.bridge === "online" ? "en ligne" : "hors ligne"}${r.devices ? `, ${r.devices} appareil(s)` : ""}.`;
}

async function pageZigbee(root) {
  $("#page-title").textContent = "Zigbee";
  let range = prefs.get("z2m-range", "24h");
  if (!Z_HOURS[range]) range = "24h";
  let filter = "all";
  let st = await api("z2m");
  let rep = await api(`z2m/report?hours=${Z_HOURS[range]}`);
  const notes = { conn: "", ha: "", map: "" };
  const rangeLabel = () => (Z_RANGES.find((r) => r[0] === range) || [0, range])[1];

  const load = async () => {
    [st, rep] = await Promise.all([api("z2m"), api(`z2m/report?hours=${Z_HOURS[range]}`)]);
  };
  const reload = async () => { await load(); draw(); };

  const connCard = () => {
    const badge = !st.enabled ? '<span class="badge">désactivé</span>'
      : st.connected ? '<span class="badge good">connecté</span>' : '<span class="badge crit">déconnecté</span>';
    return `<div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Connexion au broker MQTT</h2>${badge}
        <div class="right">${st.enabled ? '<button class="btn" id="z-off">Désactiver</button>' : ""}</div></div>
      ${!st.mqtt_configured ? `<p class="muted" style="font-size:12.5px;margin:0 0 10px">Indiquez le broker MQTT auquel Zigbee2MQTT est connecté (souvent Mosquitto). NetWatch s'y abonne pour suivre la disponibilité de chaque appareil Zigbee.</p>` : ""}
      ${st.enabled && st.error ? `<div class="banner" style="border-color:var(--critical)">${esc(st.error)}</div>` : ""}
      ${st.vault_locked ? `<div class="banner">Coffre verrouillé : impossible d'enregistrer un mot de passe.</div>` : ""}
      <div class="z-form">
        <label>Adresse du broker<input type="text" id="z-host" value="${esc(st.host)}" placeholder="192.168.1.11" autocomplete="off"></label>
        <label>Port<input type="number" id="z-port" value="${esc(st.port)}" min="1" max="65535"></label>
        <label>Utilisateur<input type="text" id="z-user" value="${esc(st.user)}" autocomplete="off"></label>
        <label>Mot de passe<input type="password" id="z-pw" autocomplete="new-password" placeholder="${st.has_password ? "•••••••• (enregistré)" : ""}"></label>
        <label>Topic de base<input type="text" id="z-topic" value="${esc(st.topic)}"></label>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn primary" id="z-save">Enregistrer et activer</button>
        <button class="btn" id="z-test" ${st.mqtt_configured ? "" : "disabled"}>Tester</button>
        ${st.has_password ? '<button class="btn" id="z-pw-del">Supprimer le mot de passe</button>' : ""}
      </div>
      <div class="muted" style="font-size:12.5px;margin-top:8px">${esc(notes.conn)}</div>
    </div>`;
  };

  const toolsCard = () => `
    <div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Historique et topologie</h2></div>
      <p class="muted" style="font-size:12.5px;margin:0 0 10px"><b>Importer depuis Home Assistant</b> : Zigbee2MQTT ne garde aucun historique. NetWatch peut relire celui de Home Assistant (entités « indisponibles » = appareil hors ligne) pour diagnostiquer les dernières heures sans attendre. Jeton d'accès longue durée : profil Home Assistant → Sécurité.</p>
      <div class="z-form">
        <label>URL de Home Assistant<input type="text" id="z-ha-url" value="${esc(st.ha.url)}" placeholder="http://192.168.1.11:8123" autocomplete="off"></label>
        <label>Jeton d'accès<input type="password" id="z-ha-token" autocomplete="new-password" placeholder="${st.ha.has_token ? "•••••••• (enregistré)" : ""}"></label>
      </div>
      <label class="check" style="margin-bottom:10px;font-size:13px"><input type="checkbox" id="z-ha-insecure" ${st.ha.verify_tls ? "" : "checked"}> Ignorer le certificat (HTTPS auto-signé)</label>
      ${st.ha.url && st.ha.url_allowed === false ? `<div class="banner" style="border-color:var(--critical)">URL refusée : le jeton ne part que vers une adresse locale (IP privée ou nom .local).</div>` : ""}
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn" id="z-ha-save">Enregistrer</button>
        <button class="btn primary" id="z-ha-import">Importer l'historique</button>
        ${st.ha.has_token ? '<button class="btn" id="z-ha-del">Supprimer le jeton</button>' : ""}
      </div>
      <div class="muted" style="font-size:12.5px;margin-top:8px">${esc(notes.ha)}</div>
      <hr style="border:0;border-top:1px solid var(--border);margin:16px 0">
      <p class="muted" style="font-size:12.5px;margin:0 0 10px"><b>Carte du réseau</b> : demande à Zigbee2MQTT la liste des liens entre appareils, pour savoir par quel routeur passe chacun. Elle génère du trafic Zigbee (1 à 2 min) : lancez-la quand le réseau est calme.${st.networkmap_ts ? ` Dernière carte : ${ago(st.networkmap_ts)}.` : ""}</p>
      <button class="btn" id="z-map" ${st.connected ? "" : "disabled"}>Demander la carte</button>
      <div class="muted" style="font-size:12.5px;margin-top:8px">${esc(notes.map)}</div>
    </div>`;

  const kpis = () => {
    const s = rep.summary, info = st.info || {};
    const down = !st.connected || st.bridge === false;
    return `<div class="grid kpis">
      <div class="card kpi ${down ? "alert" : ""}"><div class="label">${icon("iot", 15)} Zigbee2MQTT</div>
        <div class="value" style="font-size:20px">${!st.connected ? "Déconnecté" : st.bridge === false ? "Pont hors ligne" : "En ligne"}</div>
        <div class="foot">${esc(info.version ? `v${info.version}` : "")}${st.last_message ? ` · message ${ago(st.last_message)}` : ""}</div></div>
      <div class="card kpi"><div class="label">Appareils</div><div class="value">${st.devices}</div>
        <div class="foot">${st.online} en ligne · ${st.offline} hors ligne</div></div>
      <div class="card kpi ${s.drops ? "alert" : ""}"><div class="label">Déconnexions (${rangeLabel()})</div><div class="value">${s.drops}</div>
        <div class="foot">${s.flapping} appareil(s) instable(s)</div></div>
      <div class="card kpi"><div class="label">Disponibilité</div><div class="value" style="font-size:24px">${pct(s.availability_pct, 2)}</div>
        <div class="foot">${s.clusters ? `${s.clusters} coupure(s) groupée(s)` : "moyenne des appareils"}</div></div>
      <div class="card kpi"><div class="label">Canal Zigbee</div><div class="value">${esc(info.channel ?? "—")}</div>
        <div class="foot">${esc(info.coordinator || "")}${info.coordinator_fw ? ` · fw ${esc(info.coordinator_fw)}` : ""}</div></div>
    </div>`;
  };

  const visibleDevices = () => rep.devices.filter((d) => filter === "all" || zBad(d));

  const deviceRows = () => {
    const list = visibleDevices();
    if (!list.length) return `<tr><td colspan="7" class="muted" style="padding:16px">Aucun appareil à afficher.</td></tr>`;
    return list.map((d, i) => `<tr>
      <td><b>${esc(d.name)}</b> ${d.guess ? `<span class="badge" title="${esc(d.guess.evidence.join(" · "))}">déduit · confiance ${esc(d.guess.confidence)}</span>` : ""} ${d.online === false ? '<span class="badge crit">hors ligne</span>' : ""}
        <div class="z-sub">${d.z2m_name ? `Z2M : ${esc(d.z2m_name)} · ` : ""}${d.guess ? `${esc(d.guess.evidence.join(" · "))} · ` : ""}${esc(Z_TYPE[d.type] || d.type || "")}${d.vendor ? ` · ${esc(d.vendor)} ${esc(d.model || "")}` : ""}${d.parent ? ` · via ${esc(d.parent)}` : ""}</div></td>
      <td style="${lqiColor(d.lqi_avg)}">${esc(d.lqi_avg ?? "—")}${d.lqi_min != null && d.lqi_min !== d.lqi_avg ? `<div class="z-sub">min ${esc(d.lqi_min)}</div>` : ""}</td>
      <td>${d.battery != null ? `<span style="${d.battery <= 15 ? "color:var(--critical-text)" : ""}">${esc(d.battery)} %</span>` : "—"}</td>
      <td><span class="badge ${d.drops >= 8 ? "crit" : d.drops >= 3 ? "new" : ""}">${d.drops}</span></td>
      <td>${d.offline_s ? fmtDur(d.offline_s) : "—"}<div class="z-sub">${d.availability_pct != null ? pct(d.availability_pct, 2) : "pas de données"}</div></td>
      <td><div class="z-strip" data-i="${i}"></div></td>
      <td>${d.errors.total ? `${d.errors.total}<div class="z-sub">${d.errors.delivery} envoi · ${d.errors.route} route</div>` : "—"}${d.announces >= 2 ? `<div class="z-sub">${d.announces} ré-annonces</div>` : ""}</td></tr>`).join("");
  };

  const clustersCard = () => !rep.clusters.length ? "" : `
    <div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Coupures groupées</h2><span class="sub">plusieurs appareils tombent en même temps</span></div>
      <ul class="z-clusters">${rep.clusters.map((c) => `<li><b>${fmtDateTime(c.ts)}</b> · <span class="badge ${c.cause === "group" ? "new" : "crit"}">${Z_CAUSE[c.cause]}</span>
        ${c.n} appareil(s) sur ${c.of}${c.back_after_s != null ? `, de retour après ${fmtDur(c.back_after_s)}` : ""}
        <div class="z-sub">${c.devices.map(esc).join(", ")}${c.shared_parent ? ` — parent commun : ${esc(c.shared_parent)}` : c.routers.length ? ` — routeur(s) concerné(s) : ${c.routers.map(esc).join(", ")}` : ""}${c.from_ha ? " — source : historique Home Assistant" : ""}</div></li>`).join("")}</ul></div>`;

  const logCard = () => !rep.log.length ? "" : `
    <div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Journal Zigbee2MQTT</h2><span class="sub">avertissements, erreurs et événements du réseau</span></div>
      <ul class="events">${rep.log.map((l) => `<li>${sevIcon(l.level === "error" ? "critical" : l.level === "warning" ? "warning" : "info")}
        <div class="msg">${l.kind === "log" ? esc(l.message) : `${esc(l.device || l.message)} ${esc(Z_LOG[l.kind] || l.kind)}`}<div class="type">${esc(l.kind === "log" ? (l.cat === "other" ? "journal" : l.cat) : "réseau")}</div></div>
        <span class="when" title="${fmtDateTime(l.ts)}">${ago(l.ts)}</span></li>`).join("")}</ul></div>`;

  const draw = () => {
    const cov = rep.coverage, s = rep.summary, v = rep.verdict;
    const sev = v.severity === "good" ? "info" : v.severity;
    root.innerHTML = `
      ${!st.mqtt_configured || !st.enabled ? connCard() : ""}
      ${st.enabled ? `
        ${st.connected && !st.availability_seen && st.info?.availability_enabled === false ? `<div class="banner" style="border-color:var(--warning)">La disponibilité des appareils n'est pas activée dans Zigbee2MQTT (<span class="mono">availability: true</span>) : aucune déconnexion ne peut être comptée.</div>` : ""}
        ${!cov.complete ? `<div class="banner">${cov.since ? `Données disponibles depuis ${fmtDur(Math.round(cov.hours * 3600))} seulement (sur ${rangeLabel()} demandées).` : "Aucune donnée de disponibilité reçue pour l'instant."} Le diagnostic se précise avec le temps ; vous pouvez aussi importer l'historique de Home Assistant (en bas de page).</div>` : ""}
        ${kpis()}
        <div class="card ${v.severity === "critical" || v.severity === "warning" ? "sev-" + v.severity : ""}" style="margin-bottom:16px">
          <div class="card-h"><h2>Diagnostic sur ${rangeLabel()}</h2><div class="right">${segHTML("r-z", Z_RANGES, range)}</div></div>
          <div style="display:flex;gap:10px;align-items:center;font-size:15px">${sevIcon(sev)}<b>${esc(v.text)}</b></div>
          ${rep.findings.map((f) => `<div class="finding sev-${f.severity}"><div class="finding-h">${sevIcon(f.severity)}<b>${esc(f.title)}</b></div>
            ${f.detail ? `<div class="finding-d">${esc(f.detail)}</div>` : ""}
            ${f.suggestion ? `<div class="finding-s">${icon("info", 13)} ${esc(f.suggestion)}</div>` : ""}</div>`).join("")}
        </div>
        <div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Appareils hors ligne simultanément</h2><span class="sub">${s.drops} déconnexion(s), ${s.errors} erreur(s) dans le journal</span></div><div id="ch-z"></div></div>
        ${clustersCard()}
        <div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Appareils</h2><div class="right">${segHTML("f-z", [["all", "Tous"], ["bad", "À surveiller"]], filter)}</div></div>
          <div class="table-wrap"><table class="table-plain"><thead><tr><th>Appareil</th><th>LQI</th><th>Pile</th><th>Déco.</th><th>Hors ligne</th><th>Disponibilité sur ${rangeLabel()}</th><th>Erreurs</th></tr></thead><tbody>${deviceRows()}</tbody></table></div></div>
        ${logCard()}
        ${toolsCard()}
        ${connCard()}` : ""}`;
    drawStrips();
    drawChart();
    bind();
  };

  const drawStrips = () => {
    const list = visibleDevices();
    const n = 96, step = (rep.end - rep.start) / n;
    const t = Array.from({ length: n }, (_, i) => Math.round(rep.start + i * step));
    root.querySelectorAll(".z-strip").forEach((el) => {
      const d = list[+el.dataset.i];
      if (d) uptimeStrip(el, t, d.strip);
    });
  };

  const drawChart = () => {
    const el = $("#ch-z");
    if (!el) return;
    if (!rep.timeline.length || !rep.summary.with_data) { el.innerHTML = `<div class="empty" style="padding:24px">Pas encore de données.</div>`; return; }
    lineChart(el, {
      t: rep.timeline.map((p) => p.ts), height: 200, label: "Appareils hors ligne",
      yMax: Math.max(3, ...rep.timeline.map((p) => p.offline)), yFmt: (v) => String(Math.round(v)),
      series: [{ name: "Hors ligne", values: rep.timeline.map((p) => p.offline), color: "--critical", area: true }],
    });
  };

  const bind = () => {
    const say = (k, t) => { notes[k] = t; draw(); };
    const tryDo = (k, fn) => async () => { try { await fn(); } catch (e) { say(k, "Échec : " + e.message); } };
    bindSeg("r-z", async (k) => { range = k; prefs.set("z2m-range", k); await reload(); });
    bindSeg("f-z", (k) => { filter = k; draw(); });
    $("#z-off")?.addEventListener("click", tryDo("conn", async () => {
      await api("settings", { method: "PATCH", body: { z2m_enabled: false } });
      notes.conn = "";
      await reload();
    }));
    $("#z-save")?.addEventListener("click", tryDo("conn", async () => {
      const host = $("#z-host").value.trim();
      if (!host) return say("conn", "Indiquez l'adresse du broker.");
      await api("settings", { method: "PATCH", body: {
        mqtt_host: host, mqtt_port: $("#z-port").value.trim() || "1883", mqtt_user: $("#z-user").value.trim(),
        z2m_topic: $("#z-topic").value.trim() || "zigbee2mqtt", z2m_enabled: true } });
      const pw = $("#z-pw").value;
      if (pw) await api("z2m/mqtt-password", { method: "PUT", body: { password: pw } });
      notes.conn = "Enregistré. Test de la connexion…";
      await load();
      draw();
      notes.conn = zTestMessage(await api("z2m/test", { method: "POST" }));
      await reload();
    }));
    $("#z-test")?.addEventListener("click", tryDo("conn", async () => {
      notes.conn = "Test en cours…";
      draw();
      notes.conn = zTestMessage(await api("z2m/test", { method: "POST" }));
      draw();
    }));
    $("#z-pw-del")?.addEventListener("click", tryDo("conn", async () => {
      if (!confirm("Supprimer le mot de passe MQTT enregistré ?")) return;
      await api("z2m/mqtt-password", { method: "DELETE" });
      await reload();
    }));
    // enregistre l'URL, la case « ignorer le certificat » et le jeton saisis (lus avant tout redessin)
    const saveHa = async () => {
      const url = $("#z-ha-url").value.trim(), insecure = $("#z-ha-insecure").checked, tok = $("#z-ha-token").value;
      await api("settings", { method: "PATCH", body: { ha_url: url, ha_verify_tls: !insecure } });
      if (tok) await api("z2m/ha-token", { method: "PUT", body: { token: tok } });
    };
    $("#z-ha-save")?.addEventListener("click", tryDo("ha", async () => {
      await saveHa();
      notes.ha = "Enregistré.";
      await reload();
    }));
    $("#z-ha-del")?.addEventListener("click", tryDo("ha", async () => {
      if (!confirm("Supprimer le jeton Home Assistant enregistré ?")) return;
      await api("z2m/ha-token", { method: "DELETE" });
      await reload();
    }));
    $("#z-ha-import")?.addEventListener("click", tryDo("ha", async () => {
      await saveHa();
      notes.ha = "Import en cours (quelques secondes)…";
      draw();
      const r = await api("z2m/import", { method: "POST", body: { hours: Math.max(24, Z_HOURS[range]) } });
      notes.ha = !r.ok ? "Échec : " + r.error
        : `${r.matched} appareil(s) sur ${r.devices} retrouvés dans Home Assistant, ${r.drops} déconnexion(s) relevée(s).`
          + (r.named ? ` ${r.named} nom(s) d'appareil récupéré(s).` : "") + (r.guessed ? ` ${r.guessed} nom(s) déduit(s) (pièce, automatisations, type).` : "") + (r.warning ? " " + r.warning : "")
          + (r.unmatched.length ? ` Non retrouvés : ${r.unmatched.join(", ")}.` : "");
      await reload();
    }));
    $("#z-map")?.addEventListener("click", tryDo("map", async () => {
      const r = await api("z2m/networkmap", { method: "POST" });
      say("map", r.ok ? "Demande envoyée : la carte arrive en 1 à 2 minutes (l'écran se met à jour tout seul)." : "Échec : " + r.error);
    }));
  };

  draw();
  state.refresh = async () => { await load(); draw(); };
}

// ------------------------------------------------------------------ page : Wi-Fi
const WIFI_RANGES = [["24h", "24 h"], ["7d", "7 j"], ["30d", "30 j"]];
const LEVEL = { critical: ["crit", "Problème"], warning: ["new", "À surveiller"], info: ["", "Info"], ok: ["good", "Stable"] };
const END_LABEL = { drop: "Coupure", roam: "Changement de point d'accès", band: "Changement de bande", gap: "Relevé interrompu" };
const bandLabel = (b) => (b == null ? "?" : b === "MLO" ? "MLO" : `${b} GHz`);

async function pageWifi(root) {
  $("#page-title").textContent = "Wi-Fi";
  let range = prefs.get("wifi-range", "24h");
  let open = null;

  const draw = async () => {
    const [d, b] = await Promise.all([api(`box/wifi?range=${range}`), api("box")]);
    const recos = d.recommendations || [];
    const bands = d.radios?.bands || {};
    const hours = Math.round((d.span || 0) / 3600);
    root.innerHTML = `
      ${!b.enabled || !b.has_credentials || !b.wifi_tracking ? `<div class="banner">Le suivi Wi-Fi s'appuie sur votre box : activez-la, enregistrez ses identifiants et laissez le suivi Wi-Fi actif dans <a href="#/box">Box</a>.</div>` : ""}
      ${recos.length ? `<div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Réglages de la box à revoir</h2><span class="sub">connus pour provoquer des coupures</span></div>
        ${recos.map((r) => `<div class="finding"><div class="finding-h"><span class="badge ${LEVEL[r.level]?.[0] || ""}">${r.level === "warning" ? "Important" : "Conseil"}</span> <strong>${esc(r.title)}</strong></div>
          <div class="muted" style="font-size:13px;margin-top:4px">${esc(r.detail)}</div></div>`).join("")}</div>` : ""}
      ${Object.keys(bands).length ? `<div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Radios de la box</h2><span class="sub">les changements de canal sont notés dans les événements</span></div>
        <div class="table-wrap"><table class="table-plain"><thead><tr><th>Bande</th><th>Canal</th><th>Largeur</th><th>Norme</th><th>Réseau</th><th>Sécurité</th></tr></thead><tbody>
        ${Object.entries(bands).map(([k, r]) => `<tr><td>${k} GHz</td><td>${r.channel ?? "—"}${r.dfs ? ' <span class="badge new">radar</span>' : ""}</td><td>${r.width ? r.width + " MHz" : "—"}</td><td>${esc(r.standard || "—")}</td><td>${esc(r.ssid || "—")}</td><td>${esc(r.security || "—")}</td></tr>`).join("")}
        ${d.radios?.mlo?.enabled ? `<tr><td>MLO</td><td colspan="3">multi-bandes (Wi-Fi 7)</td><td>${esc(d.radios.mlo.ssid || "—")}</td><td>${esc(d.radios.mlo.security || "—")}</td></tr>` : ""}
        </tbody></table></div></div>` : ""}
      <div class="card"><div class="card-h"><h2>Appareils Wi-Fi</h2>
        <span class="sub">${hours ? `${hours} h de relevés` : "pas encore de relevé"} · les plus touchés d'abord</span>
        <div class="right">${segHTML("r-wifi", WIFI_RANGES, range)}</div></div>
        ${d.devices.length ? `<div class="table-wrap"><table><thead><tr><th>Appareil</th><th>Point d'accès</th><th>Signal</th><th>Coupures</th><th>Chang. AP</th><th>Connecté</th><th>Ping</th><th>Diagnostic</th></tr></thead><tbody>
        ${d.devices.map((s) => `<tr class="wifi-row" data-mac="${esc(s.mac)}" style="cursor:pointer">
          <td>${esc(s.name)}${s.random_mac ? ' <span class="badge" title="Adresse MAC aléatoire (Android)">MAC privée</span>' : ""}${s.online ? "" : ' <span class="badge">absent</span>'}</td>
          <td>${esc(s.ap)} · ${esc(bandLabel(s.band))}</td>
          <td>${s.rssi_avg != null ? `${s.rssi_avg.toFixed(0)} dBm` : "—"}</td>
          <td><strong>${s.drops}</strong></td><td>${s.roams + s.bands}</td>
          <td>${fmtDur(s.connected_s)}</td>
          <td>${s.ping_up != null ? pct(s.ping_up * 100, 0) : "—"}</td>
          <td><span class="badge ${LEVEL[s.worst][0]}">${LEVEL[s.worst][1]}</span></td></tr>
          <tr class="wifi-detail" id="wd-${esc(s.mac.replace(/:/g, ""))}" style="display:none"><td colspan="8"></td></tr>`).join("")}
        </tbody></table></div>`
        : `<div class="empty" style="padding:16px">Aucun appareil Wi-Fi suivi pour l'instant. Les relevés commencent dès que la box est interrogée avec ses identifiants.</div>`}
      </div>`;
    bindSeg("r-wifi", (k) => { range = k; prefs.set("wifi-range", k); open = null; draw(); });
    root.querySelectorAll(".wifi-row").forEach((tr) => tr.addEventListener("click", () => toggle(tr.dataset.mac, d)));
    if (open) toggle(open, d, true);
  };

  const toggle = async (mac, d, keep) => {
    const row = $(`#wd-${mac.replace(/:/g, "")}`);
    if (!row) return;
    const show = keep || row.style.display === "none";
    root.querySelectorAll(".wifi-detail").forEach((r) => { r.style.display = "none"; });
    if (!show) { open = null; return; }
    open = mac;
    const s = d.devices.find((x) => x.mac === mac);
    const det = await api(`box/wifi/${mac}?range=${range}`);
    row.style.display = "";
    const share = (o) => { const t = Object.values(o).reduce((a, v) => a + v, 0) || 1; return Object.entries(o).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${esc(k)} ${Math.round((100 * v) / t)} %`).join(" · "); };
    row.firstElementChild.innerHTML = `
      <div style="padding:8px 4px">
        ${s.issues.map((i) => `<div style="margin-bottom:6px"><span class="badge ${LEVEL[i.level]?.[0] || ""}">${LEVEL[i.level]?.[1]}</span> ${esc(i.text)}</div>`).join("")}
        <div class="muted" style="font-size:12.5px;margin:6px 0">Temps passé — point d'accès : ${share(s.share.ap)} · bande : ${share(s.share.band)}${s.rssi_at_drop != null ? ` · signal juste avant une coupure : ${s.rssi_at_drop} dBm` : ""}${s.longest_s ? ` · plus longue connexion : ${fmtDur(s.longest_s)}` : ""}</div>
        <div id="wch"></div>
        <div class="table-wrap" style="max-height:260px;overflow:auto"><table class="table-plain"><thead><tr><th>Début</th><th>Durée</th><th>Point d'accès</th><th>Bande</th><th>Signal (début → fin)</th><th>Fin</th></tr></thead><tbody>
        ${det.sessions.map((x) => { const end = x.end ?? x.last_ts; return `<tr><td>${fmtDateTime(x.start)}</td><td>${fmtDur(Math.max(0, end - x.start))}</td><td>${esc(x.ap)}</td><td>${esc(bandLabel(x.band))}</td>
          <td>${x.rssi_first ?? "—"} → ${x.rssi_last ?? "—"} dBm</td>
          <td>${x.end == null ? '<span class="badge good">en cours</span>' : `<span class="badge ${x.end_reason === "drop" ? "crit" : ""}">${esc(END_LABEL[x.end_reason] || x.end_reason)}</span>`}</td></tr>`; }).join("")}
        </tbody></table></div></div>`;
    const pts = det.series.filter((p) => p.rssi != null);
    if (pts.length > 1) {
      // l'axe du graphique part de 0 : on trace « qualité » = signal + 100 (0 = très mauvais, 70 = excellent)
      lineChart($("#wch"), {
        t: pts.map((p) => p.ts), height: 170, yFmt: (v) => `${Math.round(v - 100)} dBm`, tipFmt: (v) => `${Math.round(v - 100)} dBm`,
        label: "Signal Wi-Fi", series: [{ name: "Signal", values: pts.map((p) => p.rssi + 100), color: "--s1", area: true }],
      });
    }
  };

  await draw();
  state.refresh = null;
}

// ------------------------------------------------------------------ environnement radio (Wi-Fi voisins, Zigbee)
async function pageRadio(root) {
  $("#page-title").textContent = "Radio";
  const d = await api("air");
  const tok = (await api("air/token")).token;
  const base = location.origin;
  const cmd = `.\\netwatch-wifi-agent.ps1 -Url ${base} -Token ${tok}`;
  const bar = (v, max, cls = "") => `<div style="background:var(--border,#8884);border-radius:4px;height:8px;min-width:80px"><div class="${cls}" style="width:${Math.min(100, max ? (100 * v) / max : 0)}%;height:8px;border-radius:4px;background:var(--s1,#4c8bf5)"></div></div>`;
  const agent = `<div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Agent de scan</h2><span class="sub">le serveur n'a pas de carte Wi-Fi : un PC l'alimente</span></div>
    <div class="muted" style="font-size:13px;margin-bottom:8px">Sur un PC Windows allumé, lancez dans PowerShell (le script est dans <code>tools/netwatch-wifi-agent.ps1</code>) :</div>
    <pre style="white-space:pre-wrap;word-break:break-all;margin:0 0 8px;padding:8px;border-radius:6px;background:var(--border,#8882)">${esc(cmd)}</pre>
    <button class="btn" id="air-regen">Régénérer le jeton</button> <span class="muted" style="font-size:12.5px">Le jeton ne sert qu'à envoyer des scans.</span></div>`;
  let body = "";
  if (!d.available) {
    body = `<div class="card empty" style="margin-bottom:16px">Aucun scan reçu pour l'instant. Lancez l'agent ci-dessous.</div>`;
  } else {
    const max24 = Math.max(...d.wifi24.map((x) => x.score), 0.01);
    const maxZ = Math.max(...d.zigbee.map((x) => x.score), 0.01);
    body = `
      ${d.stale ? `<div class="banner">Dernier scan reçu ${ago(d.ts)} : l'agent ne tourne plus ?</div>` : ""}
      <div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Constats</h2><span class="sub">scan de ${esc(d.host || "?")} ${ago(d.ts)} · ${d.counts["2.4"]} AP en 2,4 GHz, ${d.counts["5"]} en 5 GHz, ${d.counts["6"]} en 6 GHz</span></div>
        ${d.findings.length ? d.findings.map((r) => `<div class="finding"><div class="finding-h"><span class="badge ${LEVEL[r.level]?.[0] || ""}">${LEVEL[r.level]?.[1] || ""}</span> <strong>${esc(r.title)}</strong></div>
          <div class="muted" style="font-size:13px;margin-top:4px">${esc(r.detail)}</div></div>`).join("") : '<div class="empty" style="padding:12px">Rien à signaler.</div>'}</div>
      <div class="grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;margin-bottom:16px">
        <div class="card"><div class="card-h"><h2>Wi-Fi 2,4 GHz</h2><span class="sub">charge par canal · meilleur : ${d.best_wifi24}</span></div>
          <table class="table-plain"><tbody>${d.wifi24.map((x) => `<tr><td>Canal ${x.channel}${x.channel === d.box_channel ? ' <span class="badge">box</span>' : ""}${x.channel === d.best_wifi24 ? ' <span class="badge good">libre</span>' : ""}</td><td style="width:50%">${bar(x.score, max24)}</td><td>${x.aps} AP</td></tr>`).join("")}</tbody></table></div>
        <div class="card"><div class="card-h"><h2>Zigbee</h2><span class="sub">gêne du Wi-Fi par canal · meilleur : ${d.best_zigbee}</span></div>
          <table class="table-plain"><tbody>${d.zigbee.map((x) => `<tr><td>Canal ${x.channel}${x.channel === d.zigbee_channel ? ' <span class="badge">actuel</span>' : ""}${x.channel === d.best_zigbee ? ' <span class="badge good">libre</span>' : ""}</td><td style="width:50%">${bar(x.score, maxZ)}</td><td class="muted">${x.wifi_channels.length ? "Wi-Fi " + x.wifi_channels.join(", ") : "—"}</td></tr>`).join("")}</tbody></table></div>
      </div>
      ${d.wifi5.length ? `<div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Wi-Fi 5 GHz</h2></div>
        <div class="table-wrap"><table class="table-plain"><thead><tr><th>Canal</th><th>AP</th><th>Signal max</th><th>Occupation max</th></tr></thead><tbody>
        ${d.wifi5.map((x) => `<tr><td>${x.channel}</td><td>${x.aps}</td><td>${x.signal_max} %</td><td>${x.util_max} %</td></tr>`).join("")}</tbody></table></div></div>` : ""}
      <div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Points d'accès vus</h2><span class="sub">${d.aps.length} · du plus fort au plus faible</span></div>
        <div class="table-wrap" style="max-height:420px;overflow:auto"><table class="table-plain"><thead><tr><th>Réseau</th><th>Bande</th><th>Canal</th><th>Signal</th><th>Occupation</th><th>Stations</th><th>Norme</th></tr></thead><tbody>
        ${d.aps.map((a) => `<tr><td>${esc(a.ssid || "(masqué)")}</td><td>${esc(a.band)} GHz</td><td>${esc(a.channel)}</td><td>${esc(a.signal ?? "—")} %</td><td>${a.util != null ? esc(a.util) + " %" : "—"}</td><td>${esc(a.stations ?? "—")}</td><td>${esc(a.radio || "—")}</td></tr>`).join("")}</tbody></table></div></div>`;
  }
  root.innerHTML = body + agent;
  $("#air-regen")?.addEventListener("click", async () => {
    if (!confirm("Régénérer le jeton ? L'agent devra être relancé avec le nouveau.")) return;
    await api("air/token", { method: "POST" });
    pageRadio(root);
  });
  state.refresh = () => pageRadio(root);
}

// ------------------------------------------------------------------ routeur
async function route() {
  state.refresh = null;
  const root = $("#content");
  const [path, qs] = (location.hash.slice(1) || "/").split("?");
  const params = new URLSearchParams(qs || "");
  renderNav();
  try {
    let m;
    if (path === "/" || path === "") await pageDashboard(root);
    else if (path === "/devices") await pageDevices(root, params);
    else if ((m = path.match(/^\/device\/(\d+)$/))) await pageDevice(root, +m[1]);
    else if (path === "/latency") await pageLatency(root);
    else if (path === "/diagnostic") await pageDiagnostic(root);
    else if (path === "/box" || path === "/bbox") await pageBox(root);
    else if (path === "/wifi") await pageWifi(root);
    else if (path === "/radio") await pageRadio(root);
    else if (path === "/zigbee") await pageZigbee(root);
    else if (path === "/credentials") await pageCredentials(root);
    else if (path === "/notifications") await pageNotifications(root);
    else if (path === "/settings") await pageSettings(root);
    else if (path === "/events") await pageEvents(root);
    else if (path === "/scans") await pageScans(root);
    else root.innerHTML = `<div class="empty">Page introuvable</div>`;
  } catch (e) {
    console.error(e);
    root.innerHTML = `<div class="card empty">Erreur de chargement : ${esc(e.message)}</div>`;
  }
  window.scrollTo(0, 0);
}

// ------------------------------------------------------------------ temps réel (SSE)
const sse = { connected: false, timer: null };
function connectSSE() {
  const es = new EventSource("/api/stream");
  es.onopen = () => { sse.connected = true; renderLive(); };
  es.onerror = () => { sse.connected = false; renderLive(); };
  es.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.type === "event") {
      const e = msg.event;
      if (e.severity !== "info" || e.type === "new_device") {
        toast(`${sevIcon(e.severity)} <b>${esc(EV_LABEL[e.type] || e.type)}</b><div class="t2" style="margin-top:4px">${esc(e.message)}</div>`);
      }
    }
    // regroupe les rafraîchissements (plusieurs messages par cycle)
    clearTimeout(sse.timer);
    sse.timer = setTimeout(async () => {
      await loadOverview();
      if (state.refresh && !document.activeElement?.matches("input, textarea, select")) state.refresh().catch(console.warn);
    }, 800);
  };
}

// ------------------------------------------------------------------ biométrie (WebAuthn)
const biometrySupported = () => !!window.PublicKeyCredential;
function b64urlToBuf(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from([...atob(b64)].map((c) => c.charCodeAt(0))).buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function serializeCred(cred) {
  const r = cred.response;
  const out = {
    id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    response: { clientDataJSON: bufToB64url(r.clientDataJSON) },
  };
  if (r.attestationObject) {
    out.response.attestationObject = bufToB64url(r.attestationObject);
    out.response.transports = r.getTransports ? r.getTransports() : [];
  } else {
    out.response.authenticatorData = bufToB64url(r.authenticatorData);
    out.response.signature = bufToB64url(r.signature);
    out.response.userHandle = r.userHandle ? bufToB64url(r.userHandle) : null;
  }
  return out;
}
async function passkeyRegister(name) {
  const r = await api("webauthn/register/options", { method: "POST" });
  const opts = r.options;
  opts.challenge = b64urlToBuf(opts.challenge);
  opts.user.id = b64urlToBuf(opts.user.id);
  (opts.excludeCredentials || []).forEach((c) => (c.id = b64urlToBuf(c.id)));
  const cred = await navigator.credentials.create({ publicKey: opts });
  await api("webauthn/register/verify", { method: "POST", body: { state: r.state, name, credential: serializeCred(cred) } });
}
async function passkeyLogin() {
  const r = await fetch("/api/webauthn/auth/options", { method: "POST" }).then((x) => x.json());
  if (r.error) throw new Error(r.error);
  const opts = r.options;
  opts.challenge = b64urlToBuf(opts.challenge);
  (opts.allowCredentials || []).forEach((c) => (c.id = b64urlToBuf(c.id)));
  const cred = await navigator.credentials.get({ publicKey: opts });
  const res = await fetch("/api/webauthn/auth/verify", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ state: r.state, credential: serializeCred(cred) }),
  });
  if (!res.ok) { const j = await res.json().catch(() => ({})); throw new Error(j.error || "échec"); }
}

// ------------------------------------------------------------------ authentification
function authOverlay(html) {
  const el = document.createElement("div");
  el.className = "auth-overlay";
  el.innerHTML = html;
  document.body.appendChild(el);
  return el;
}

function showLogin(msg) {
  if ($(".auth-overlay")) {
    if (msg) $("#login-msg") && ($("#login-msg").textContent = msg);
    return;
  }
  const showBio = state.auth?.passkeys && biometrySupported();
  const el = authOverlay(`
    <form class="auth-card" id="login-form" autocomplete="on">
      <div class="auth-brand">${icon("lock", 22)} NetWatch</div>
      ${showBio ? `<button class="btn primary" type="button" id="login-bio" style="justify-content:center">${icon("user", 16)} Se connecter avec la biométrie</button>
      <div class="auth-sep">ou</div>` : ""}
      <label>Identifiant<input id="login-user" autocomplete="username" ${showBio ? "" : "autofocus"}></label>
      <label>Mot de passe<input id="login-pass" type="password" autocomplete="current-password"></label>
      <div class="auth-msg" id="login-msg">${msg ? esc(msg) : ""}</div>
      <button class="btn ${showBio ? "" : "primary"}" type="submit">Se connecter</button>
    </form>`);
  $("#login-bio", el)?.addEventListener("click", async () => {
    $("#login-msg").textContent = "Vérification biométrique…";
    try { await passkeyLogin(); el.remove(); startApp(); }
    catch (e) { $("#login-msg").textContent = "Biométrie : " + e.message; }
  });
  const form = $("#login-form", el);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = form.querySelector("button");
    btn.disabled = true;
    try {
      const r = await fetch("/api/login", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: $("#login-user").value, password: $("#login-pass").value }),
      });
      if (r.ok) { el.remove(); startApp(); return; }
      const j = await r.json().catch(() => ({}));
      $("#login-msg").textContent = j.error || "Échec de la connexion.";
    } catch { $("#login-msg").textContent = "Serveur injoignable."; }
    btn.disabled = false;
  });
}

function showSetup(defaultUser) {
  if ($(".auth-overlay")) return;
  const el = authOverlay(`
    <form class="auth-card" id="setup-form" autocomplete="on">
      <div class="auth-brand">${icon("lock", 22)} NetWatch</div>
      <h2 style="margin:0;font-size:15px">Bienvenue — crée ton compte administrateur</h2>
      <p class="muted" style="font-size:12.5px;margin:0">Ce mot de passe protégera l'accès à NetWatch. Aucune variable d'environnement n'est nécessaire.</p>
      <label>Identifiant<input id="setup-user" autocomplete="username" value="${esc(defaultUser || "admin")}"></label>
      <label>Mot de passe (8 caractères min.)<input id="setup-pass" type="password" autocomplete="new-password" autofocus></label>
      <label>Confirmer<input id="setup-pass2" type="password" autocomplete="new-password"></label>
      <div class="auth-msg" id="setup-msg"></div>
      <button class="btn primary" type="submit">Créer le compte</button>
    </form>`);
  $("#setup-form", el).addEventListener("submit", async (e) => {
    e.preventDefault();
    const m = $("#setup-msg");
    const pw = $("#setup-pass").value;
    if (pw.length < 8) { m.textContent = "Au moins 8 caractères."; return; }
    if (pw !== $("#setup-pass2").value) { m.textContent = "Les mots de passe ne correspondent pas."; return; }
    const btn = e.target.querySelector("button");
    btn.disabled = true;
    try {
      const r = await fetch("/api/setup", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: $("#setup-user").value, password: pw }),
      });
      if (r.ok) {
        const j = await r.json().catch(() => ({}));
        state.auth = { auth_required: true, authenticated: true, username: j.username, wizard_required: true };
        el.remove(); toast("Compte créé ✓"); startApp(); return;
      }
      const j = await r.json().catch(() => ({}));
      m.textContent = j.error || "Échec de la configuration.";
    } catch { m.textContent = "Serveur injoignable."; }
    btn.disabled = false;
  });
}

async function doLogout() {
  try { await fetch("/api/logout", { method: "POST" }); } catch { /* ignore */ }
  location.reload();
}

function showAccount() {
  if ($(".auth-overlay")) return;
  const el = authOverlay(`
    <form class="auth-card" id="acct-form">
      <div class="auth-brand">${icon("user", 20)} ${esc(state.auth?.username || "Compte")}</div>
      <h2 style="margin:0 0 4px;font-size:15px">Changer le mot de passe</h2>
      <label>Mot de passe actuel<input id="acct-cur" type="password" autocomplete="current-password"></label>
      <label>Nouveau mot de passe (8 caractères min.)<input id="acct-new" type="password" autocomplete="new-password"></label>
      <label>Confirmer<input id="acct-new2" type="password" autocomplete="new-password"></label>
      <div class="auth-msg" id="acct-msg"></div>
      <div style="display:flex;gap:8px">
        <button class="btn primary" type="submit">Enregistrer</button>
        <button class="btn" type="button" id="acct-cancel">Fermer</button>
      </div>
      <div id="acct-bio" style="border-top:1px solid var(--border);margin-top:6px;padding-top:12px"></div>
    </form>`);
  const drawBio = async () => {
    const box = $("#acct-bio", el);
    if (!box) return;
    if (!biometrySupported()) { box.innerHTML = `<div class="muted" style="font-size:12.5px">Cet appareil ne gère pas la biométrie.</div>`; return; }
    let data = { credentials: [] };
    try { data = await api("webauthn/credentials"); } catch { /* ignore */ }
    box.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><b style="font-size:13px">${icon("user", 14)} Biométrie (Face ID / empreinte)</b></div>
      ${data.credentials.length ? `<div class="chips" style="margin-bottom:8px">${data.credentials.map((c) => `<span class="badge">${esc(c.name || "Passkey")} <a href="#" data-del="${c.id}" title="Supprimer" style="margin-left:4px">✕</a></span>`).join("")}</div>` : `<div class="muted" style="font-size:12.5px;margin-bottom:8px">Aucun passkey enregistré sur ce compte.</div>`}
      <button class="btn" type="button" id="bio-add">Activer la biométrie sur cet appareil</button>
      <span class="muted" id="bio-msg" style="font-size:12.5px;margin-left:8px"></span>`;
    $("#bio-add", box).addEventListener("click", async () => {
      $("#bio-msg").textContent = "Suis l'invite de ton appareil…";
      try { await passkeyRegister(navigator.platform || "Cet appareil"); $("#bio-msg").textContent = ""; toast("Biométrie activée ✓"); drawBio(); }
      catch (e) { $("#bio-msg").textContent = "Échec : " + (e.message || e); }
    });
    box.querySelectorAll("[data-del]").forEach((a) => a.addEventListener("click", async (ev) => {
      ev.preventDefault();
      await api(`webauthn/credentials/${a.dataset.del}`, { method: "DELETE" });
      drawBio();
    }));
  };
  drawBio();
  $("#acct-cancel", el).addEventListener("click", () => el.remove());
  el.addEventListener("click", (e) => { if (e.target === el) el.remove(); });
  $("#acct-form", el).addEventListener("submit", async (e) => {
    e.preventDefault();
    const m = $("#acct-msg");
    if ($("#acct-new").value !== $("#acct-new2").value) { m.textContent = "Les mots de passe ne correspondent pas."; return; }
    try {
      const r = await fetch("/api/password", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current: $("#acct-cur").value, new: $("#acct-new").value }),
      });
      if (r.ok) { el.remove(); toast("Mot de passe changé ✓"); }
      else { const j = await r.json().catch(() => ({})); m.textContent = j.error || "Échec."; }
    } catch { m.textContent = "Serveur injoignable."; }
  });
}

// ------------------------------------------------------------------ assistant de configuration
const WIZ_KEYS = ["scans_enabled", "deep_enabled", "ssh_enabled", "diag_enabled", "box_enabled", "wifi_tracking",
  "z2m_enabled", "z2m_topic", "mqtt_host", "mqtt_port", "mqtt_user"];

async function showWizard() {
  if ($(".wiz-overlay")) return;
  const w = await api("wizard");
  const sel = {};
  WIZ_KEYS.forEach((k) => { sel[k] = w.settings[k] ?? (typeof w.settings[k] === "boolean" ? false : ""); });
  if (!sel.mqtt_port) sel.mqtt_port = 1883;
  if (!sel.z2m_topic) sel.z2m_topic = "zigbee2mqtt";
  const mq = { password: "" };
  let step = 0, b = w.box, detectTried = false;
  const STEPS = ["Bienvenue", "Réseau", "Box Internet", "Zigbee", "Terminer"];
  const el = document.createElement("div");
  el.className = "auth-overlay wiz-overlay";
  document.body.appendChild(el);

  const toggle = (key, label, help) => `
    <label class="check" style="align-items:flex-start;margin:10px 0;display:flex">
      <span class="switch"><input type="checkbox" data-sel="${key}" ${sel[key] ? "checked" : ""}><span></span></span>
      <span>${esc(label)}${help ? `<span class="muted" style="display:block;font-size:12px;font-weight:400">${esc(help)}</span>` : ""}</span>
    </label>`;
  const text = (key, label, type = "text") => `
    <label>${esc(label)}<input data-text="${key}" type="${type}" autocomplete="off" value="${key === "mqtt_password" ? "" : esc(sel[key] ?? "")}"></label>`;
  const yn = (v) => (v ? '<span class="badge good">activé</span>' : '<span class="badge">désactivé</span>');

  const content = () => {
    if (step === 0) {
      const n = w.network || {};
      return `<h2 style="margin:0;font-size:16px">Bienvenue dans NetWatch</h2>
        <p class="muted" style="font-size:13px">Cet assistant choisit ce que NetWatch surveille. Tout reste modifiable ensuite dans les Réglages, et vous pouvez le relancer à tout moment.</p>
        <div class="card" style="padding:12px;font-size:13px">
          <div>Réseau détecté : <b class="mono">${esc(n.subnet || "?")}</b></div>
          <div>Interface : <span class="mono">${esc(n.interface || "?")}</span> · NetWatch : <span class="mono">${esc(n.ip || "?")}</span></div>
          <div>Passerelle (votre box) : <span class="mono">${esc(n.gateway || "?")}</span></div>
        </div>`;
    }
    if (step === 1) {
      return `<h2 style="margin:0;font-size:16px">Surveillance du réseau</h2>
        ${toggle("scans_enabled", "Découverte des appareils (ARP + ping)", "Présence, latence et perte de chaque appareil, toutes les minutes.")}
        ${toggle("deep_enabled", "Scan des ports et services (nmap)", "Ports ouverts, services, système d'exploitation. Toutes les heures.")}
        ${toggle("ssh_enabled", "Inventaire SSH", "Lecture seule des machines Linux, si vous ajoutez des identifiants dans la page Identifiants.")}
        ${toggle("diag_enabled", "Diagnostic de latence", "Situe l'origine d'un ralentissement (box, Wi-Fi, DNS, fournisseur).")}`;
    }
    if (step === 2) {
      return `<h2 style="margin:0;font-size:16px">Box Internet</h2>
        <p class="muted" style="font-size:12.5px;margin:0">Bouygues, Free, Orange et SFR. NetWatch lit l'état de la ligne, les appareils connectés et leur point d'accès (box ou répéteur).</p>
        ${toggle("box_enabled", "Superviser ma box Internet")}
        ${sel.box_enabled ? `<div id="wiz-box" style="margin:6px 0"></div>
          ${toggle("wifi_tracking", "Suivi Wi-Fi", "Coupures, itinérance entre box et répéteurs, signal avant chaque coupure.")}` : ""}`;
    }
    if (step === 3) {
      return `<h2 style="margin:0;font-size:16px">Zigbee</h2>
        <p class="muted" style="font-size:12.5px;margin:0">Diagnostic de votre réseau Zigbee2MQTT (disponibilité, qualité des liens, routeurs). NetWatch écoute le broker MQTT, sans rien modifier.</p>
        ${toggle("z2m_enabled", "Surveiller Zigbee2MQTT")}
        ${sel.z2m_enabled ? `<div style="display:flex;flex-direction:column;gap:10px">
          ${text("mqtt_host", "Broker MQTT (adresse)")}
          ${text("mqtt_port", "Port")}
          ${text("mqtt_user", "Utilisateur (facultatif)")}
          ${text("mqtt_password", "Mot de passe (facultatif)", "password")}
          ${text("z2m_topic", "Topic de base de Zigbee2MQTT")}
          <div><button class="btn" type="button" id="wiz-z2m-test">Tester la connexion</button>
            <span class="muted" id="wiz-z2m-msg" style="font-size:12.5px;margin-left:8px"></span></div></div>` : ""}`;
    }
    const bx = sel.box_enabled ? (b.provider ? b.provider.label : "fournisseur à choisir") : "";
    return `<h2 style="margin:0;font-size:16px">Récapitulatif</h2>
      <div class="card" style="padding:12px;font-size:13px;display:grid;gap:6px">
        <div>Découverte des appareils ${yn(sel.scans_enabled)}</div>
        <div>Scan des ports et services ${yn(sel.deep_enabled)}</div>
        <div>Inventaire SSH ${yn(sel.ssh_enabled)}</div>
        <div>Diagnostic de latence ${yn(sel.diag_enabled)}</div>
        <div>Box Internet ${yn(sel.box_enabled)} ${esc(bx)}</div>
        <div>Suivi Wi-Fi ${yn(sel.box_enabled && sel.wifi_tracking)}</div>
        <div>Zigbee2MQTT ${yn(sel.z2m_enabled)}</div>
      </div>
      <p class="muted" style="font-size:12.5px">Pour recevoir des alertes sur ce téléphone ou cet ordinateur, activez les notifications dans la page <b>Notifications</b>.</p>`;
  };

  const msg = (t) => { const m = $("#wiz-msg", el); if (m) m.textContent = t; };

  const draw = () => {
    el.innerHTML = `<div class="auth-card wiz-card">
      <div class="auth-brand">${icon("lock", 22)} NetWatch</div>
      <div class="wiz-steps">${STEPS.map((s, i) => `<span class="${i === step ? "on" : i < step ? "done" : ""}">${i + 1}. ${s}</span>`).join("")}</div>
      <div class="wiz-body">${content()}</div>
      <div class="auth-msg" id="wiz-msg"></div>
      <div style="display:flex;gap:8px;justify-content:space-between;flex-wrap:wrap">
        <button class="btn" type="button" id="wiz-skip">Passer l'assistant</button>
        <span style="display:flex;gap:8px">
          ${step > 0 ? '<button class="btn" type="button" id="wiz-prev">Précédent</button>' : ""}
          <button class="btn primary" type="button" id="wiz-next">${step === STEPS.length - 1 ? "Terminer" : "Suivant"}</button>
        </span></div></div>`;
    bind();
  };

  const bind = () => {
    el.querySelectorAll("[data-sel]").forEach((i) => i.addEventListener("change", () => {
      sel[i.dataset.sel] = i.checked;
      if (["box_enabled", "z2m_enabled"].includes(i.dataset.sel)) draw();
    }));
    el.querySelectorAll("[data-text]").forEach((i) => i.addEventListener("input", () => {
      if (i.dataset.text === "mqtt_password") mq.password = i.value; else sel[i.dataset.text] = i.value;
    }));
    if (step === 2 && sel.box_enabled) {
      boxAccess($("#wiz-box", el), b, (nb) => { b = nb; draw(); });
      if (!b.provider && !detectTried) {
        detectTried = true;
        api("box/detect", { method: "POST" }).then(async (r) => {
          if (r.detected?.length === 1) r = await api("box/provider", { method: "PUT", body: { provider: r.detected[0].provider } });
          b = r;
          if (step === 2 && el.isConnected) draw();
        }).catch(() => {});
      }
    }
    $("#wiz-z2m-test", el)?.addEventListener("click", async () => {
      const m = $("#wiz-z2m-msg", el);
      m.textContent = "Test en cours…";
      try {
        await api("settings", { method: "PATCH", body: {
          z2m_enabled: true, mqtt_host: sel.mqtt_host, mqtt_port: sel.mqtt_port, mqtt_user: sel.mqtt_user, z2m_topic: sel.z2m_topic } });
        if (mq.password) await api("z2m/mqtt-password", { method: "PUT", body: { password: mq.password } });
        m.textContent = zTestMessage(await api("z2m/test", { method: "POST" }));
      } catch (e) { m.textContent = "Échec : " + e.message; }
    });
    $("#wiz-prev", el)?.addEventListener("click", () => { step--; draw(); });
    $("#wiz-next", el).addEventListener("click", async () => {
      if (step < STEPS.length - 1) { step++; draw(); return; }
      try { await finish(); } catch (e) { msg("Échec : " + e.message); }
    });
    $("#wiz-skip", el).addEventListener("click", async () => {
      await api("wizard/complete", { method: "POST" });
      close();
    });
  };

  const close = () => { el.remove(); if (state.auth) state.auth.wizard_required = false; loadOverview(); route(); };

  const finish = async () => {
    const body = {};
    WIZ_KEYS.forEach((k) => { body[k] = sel[k] ?? ""; });
    if (sel.z2m_enabled && mq.password) await api("z2m/mqtt-password", { method: "PUT", body: { password: mq.password } });
    await api("settings", { method: "PATCH", body });
    await api("wizard/complete", { method: "POST" });
    if (sel.box_enabled) api("box/refresh", { method: "POST" }).catch(() => {});
    toast("Configuration enregistrée ✓");
    close();
  };

  draw();
}

// ------------------------------------------------------------------ init
function initChrome() {
  const setThemeBtn = () => {
    const light = document.documentElement.dataset.theme === "light";
    $("#btn-theme").innerHTML = icon(light ? "moon" : "sun", 18);
  };
  setThemeBtn();
  $("#btn-theme").addEventListener("click", () => {
    const light = document.documentElement.dataset.theme !== "light";
    document.documentElement.dataset.theme = light ? "light" : "dark";
    prefs.set("theme", light ? "light" : "dark");
    try { localStorage.setItem("nw-theme", light ? "light" : "dark"); } catch { /* ignore */ }
    setThemeBtn();
    route();
  });
  $("#btn-discovery").innerHTML = `${icon("refresh", 15)} <span class="label-long">Scanner</span>`;
  $("#btn-discovery").addEventListener("click", async () => {
    const r = await api("scan/discovery", { method: "POST" });
    toast(r.queued ? "Découverte lancée" : "Découverte déjà en cours");
  });
  if (state.auth?.auth_required && !$("#btn-account")) {
    $("#btn-theme").insertAdjacentHTML("beforebegin",
      `<button class="icon-btn" id="btn-account" title="Compte / mot de passe">${icon("user", 18)}</button>`);
    $("#btn-account").addEventListener("click", showAccount);
    $("#btn-theme").insertAdjacentHTML("afterend",
      `<button class="icon-btn" id="btn-logout" title="Se déconnecter">${icon("logout", 18)}</button>`);
    $("#btn-logout").addEventListener("click", doLogout);
  }
  // lignes cliquables (pas de onclick en ligne : la CSP les interdit)
  document.addEventListener("click", (e) => {
    const row = e.target.closest?.("[data-href]");
    if (row && !e.target.closest("a, button, input, select, label")) location.hash = row.dataset.href;
  });
  setInterval(renderLive, 15000);
  setInterval(loadOverview, 60000);
}

let _appStarted = false;
function startApp() {
  if (_appStarted) return;
  _appStarted = true;
  initChrome();
  loadOverview().then(() => { connectSSE(); route(); if (state.auth?.wizard_required) showWizard(); });
}

function registerSW() {
  if (!("serviceWorker" in navigator)) return;
  let refreshing = false;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (refreshing) return;
    refreshing = true;
    location.reload();  // un nouveau service worker a pris la main -> recharge une fois
  });
  navigator.serviceWorker.register("/sw.js")
    .then((reg) => { try { reg.update(); } catch { /* ignore */ } })
    .catch((e) => console.warn("SW:", e));
}

async function boot() {
  registerSW();
  window.addEventListener("hashchange", route);
  let session = { auth_required: false, authenticated: true };
  try { session = await fetch("/api/session").then((r) => r.json()); } catch { /* ignore */ }
  state.auth = session;
  if (session.setup_required) { showSetup(session.username_default); return; }
  if (session.auth_required && !session.authenticated) { showLogin(); return; }
  startApp();
}

await boot();
