// Graphiques SVG légers, sans dépendance : courbes, heatmap, sparklines, bande de disponibilité.
const NS = "http://www.w3.org/2000/svg";
// les noms affichés (appareils, séries) viennent du réseau : toujours échappés avant innerHTML
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export const cssVar = (name) =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim();

const pad2 = (n) => String(n).padStart(2, "0");
export function fmtTime(t, span) {
  const d = new Date(t * 1000);
  if (span <= 36 * 3600) return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  return `${pad2(d.getDate())}/${pad2(d.getMonth() + 1)}`;
}
export function fmtDateTime(t) {
  const d = new Date(t * 1000);
  return `${pad2(d.getDate())}/${pad2(d.getMonth() + 1)} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}
export function fmtMs(v) {
  if (v == null) return "—";
  if (v < 1) return `${v.toFixed(2)} ms`;
  if (v < 10) return `${v.toFixed(1)} ms`;
  return `${Math.round(v)} ms`;
}

function niceTicks(max, count = 4) {
  if (!(max > 0)) return [0, 1];
  const raw = max / count;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) || raw;
  const ticks = [];
  for (let v = 0; v <= max + step * 0.001; v += step) ticks.push(+v.toFixed(6));
  if (ticks[ticks.length - 1] < max) ticks.push(+(ticks[ticks.length - 1] + step).toFixed(6));
  return ticks;
}

function el(tag, attrs = {}, parent) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) e.setAttribute(k, v);
  if (parent) parent.appendChild(e);
  return e;
}

function ensureTooltip(container) {
  let tt = container.querySelector(":scope > .tooltip");
  if (!tt) {
    tt = document.createElement("div");
    tt.className = "tooltip";
    container.appendChild(tt);
  }
  return tt;
}

function placeTooltip(tt, container, x, y) {
  const cw = container.clientWidth;
  const tw = tt.offsetWidth;
  let left = x + 14;
  if (left + tw > cw) left = x - tw - 14;
  tt.style.left = `${Math.max(0, left)}px`;
  tt.style.top = `${Math.max(0, y - 10)}px`;
}

const observers = new WeakMap();
function autoResize(container, render) {
  if (observers.has(container)) observers.get(container).disconnect();
  let w = container.clientWidth;
  const ro = new ResizeObserver(() => {
    if (Math.abs(container.clientWidth - w) > 4) {
      w = container.clientWidth;
      render();
    }
  });
  ro.observe(container);
  observers.set(container, ro);
}

/**
 * Courbe(s) temporelle(s) avec réticule + infobulle.
 * opts: { t, series:[{name, values, color, area, width}], height, yFmt, yMax, unit, band:{lo,hi,color} }
 */
export function lineChart(container, opts) {
  const render = () => drawLine(container, opts);
  render();
  autoResize(container, render);
}

function drawLine(container, o) {
  container.classList.add("chart");
  container.querySelectorAll("svg, .legend").forEach((n) => n.remove());
  const t = o.t || [];
  const H = o.height || 220;
  const W = Math.max(200, container.clientWidth);
  const m = { l: 46, r: 10, t: 8, b: 24 };
  const iw = W - m.l - m.r;
  const ih = H - m.t - m.b;
  const yFmt = o.yFmt || ((v) => String(v));
  const tipFmt = o.tipFmt || yFmt;

  if (o.series.length > 1) {
    const lg = document.createElement("div");
    lg.className = "legend";
    lg.innerHTML = o.series
      .map((s) => `<span><i style="background:${cssVar(s.color)}"></i>${esc(s.name)}</span>`)
      .join("");
    container.prepend(lg);
  }

  const svg = el("svg", { width: W, height: H, role: "img", "aria-label": o.label || "graphique" });
  container.appendChild(svg);
  if (!t.length) {
    el("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "tick" }, svg).textContent =
      "Pas encore de données";
    return;
  }

  let max = o.yMax ?? 0;
  if (o.yMax == null) {
    for (const s of o.series) for (const v of s.values) if (v != null && v > max) max = v;
    if (o.band) for (const v of o.band.hi) if (v != null && v > max && o.bandInScale) max = v;
  }
  const ticks = niceTicks(max * 1.05 || 1, 4);
  const yTop = ticks[ticks.length - 1];
  const t0 = t[0];
  const t1 = t[t.length - 1] === t0 ? t0 + 1 : t[t.length - 1];
  const X = (ts) => m.l + ((ts - t0) / (t1 - t0)) * iw;
  const Y = (v) => m.t + ih - (Math.min(v, yTop) / yTop) * ih;

  // grille + axe Y
  for (const v of ticks) {
    el("line", { x1: m.l, x2: W - m.r, y1: Y(v), y2: Y(v), class: v === 0 ? "axis-line" : "grid-line" }, svg);
    el("text", { x: m.l - 8, y: Y(v) + 4, "text-anchor": "end", class: "tick" }, svg).textContent = yFmt(v);
  }
  // axe X
  const span = t1 - t0;
  const nx = Math.max(2, Math.min(7, Math.floor(iw / 90)));
  for (let i = 0; i <= nx; i++) {
    const ts = t0 + (span * i) / nx;
    el("text", {
      x: X(ts), y: H - 6, class: "tick",
      "text-anchor": i === 0 ? "start" : i === nx ? "end" : "middle",
    }, svg).textContent = fmtTime(ts, span);
  }

  // bande min/max
  if (o.band) {
    const color = cssVar(o.band.color);
    let d = "";
    let seg = [];
    const flush = () => {
      if (seg.length > 1) {
        d += "M" + seg.map((i) => `${X(t[i])},${Y(o.band.hi[i])}`).join("L");
        d += "L" + seg.slice().reverse().map((i) => `${X(t[i])},${Y(o.band.lo[i])}`).join("L") + "Z";
      }
      seg = [];
    };
    t.forEach((_, i) => (o.band.hi[i] != null && o.band.lo[i] != null ? seg.push(i) : flush()));
    flush();
    el("path", { d, fill: color, "fill-opacity": 0.13, stroke: "none" }, svg);
  }

  // séries
  for (const s of o.series) {
    const color = cssVar(s.color);
    const segs = [];
    let cur = [];
    s.values.forEach((v, i) => {
      if (v == null) {
        if (cur.length) segs.push(cur);
        cur = [];
      } else cur.push([X(t[i]), Y(v)]);
    });
    if (cur.length) segs.push(cur);
    for (const sg of segs) {
      if (s.area && sg.length > 1) {
        const d = `M${sg[0][0]},${Y(0)}L` + sg.map((p) => p.join(",")).join("L") + `L${sg[sg.length - 1][0]},${Y(0)}Z`;
        el("path", { d, fill: color, "fill-opacity": 0.12 }, svg);
      }
      if (sg.length === 1) {
        el("circle", { cx: sg[0][0], cy: sg[0][1], r: 2, fill: color }, svg);
      } else {
        el("path", {
          d: "M" + sg.map((p) => p.join(",")).join("L"),
          fill: "none", stroke: color, "stroke-width": s.width || 2,
          "stroke-linejoin": "round", "stroke-linecap": "round",
        }, svg);
      }
    }
  }

  // survol
  const tt = ensureTooltip(container);
  const hair = el("line", { y1: m.t, y2: m.t + ih, class: "crosshair", visibility: "hidden" }, svg);
  const dots = o.series.map((s) =>
    el("circle", { r: 4, fill: cssVar(s.color), stroke: cssVar("--surface"), "stroke-width": 2, visibility: "hidden" }, svg)
  );
  const hit = el("rect", { x: m.l, y: m.t, width: iw, height: ih, fill: "transparent" }, svg);
  const hide = () => {
    tt.classList.remove("show");
    hair.setAttribute("visibility", "hidden");
    dots.forEach((d) => d.setAttribute("visibility", "hidden"));
  };
  hit.addEventListener("mouseleave", hide);
  hit.addEventListener("mousemove", (ev) => {
    const rect = svg.getBoundingClientRect();
    const x = ev.clientX - rect.left;
    const ts = t0 + ((x - m.l) / iw) * (t1 - t0);
    let i = 0;
    let best = Infinity;
    for (let k = 0; k < t.length; k++) {
      const dd = Math.abs(t[k] - ts);
      if (dd < best) { best = dd; i = k; }
    }
    const xi = X(t[i]);
    hair.setAttribute("x1", xi);
    hair.setAttribute("x2", xi);
    hair.setAttribute("visibility", "visible");
    let rows = "";
    o.series.forEach((s, k) => {
      const v = s.values[i];
      if (v == null) dots[k].setAttribute("visibility", "hidden");
      else {
        dots[k].setAttribute("cx", xi);
        dots[k].setAttribute("cy", Y(v));
        dots[k].setAttribute("visibility", "visible");
      }
      rows += `<div class="tt-r"><i style="background:${cssVar(s.color)}"></i>${esc(s.name)}<b>${v == null ? "—" : tipFmt(v)}</b></div>`;
    });
    if (o.band && o.band.hi[i] != null) {
      rows += `<div class="tt-r muted" style="font-size:11.5px">min ${tipFmt(o.band.lo[i])} · max ${tipFmt(o.band.hi[i])}</div>`;
    }
    if (o.extraTip) rows += o.extraTip(i);
    tt.innerHTML = `<div class="tt-h">${fmtDateTime(t[i])}</div>${rows}`;
    tt.classList.add("show");
    placeTooltip(tt, container, xi, ev.clientY - container.getBoundingClientRect().top);
  });
}

/** Couleur séquentielle (échelle log) entre --seq-0 (faible) et --seq-1 (fort). */
function hexToRgb(h) {
  h = h.replace("#", "");
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
}
export function seqColor(v, vmax) {
  const a = hexToRgb(cssVar("--seq-0"));
  const b = hexToRgb(cssVar("--seq-1"));
  const k = Math.max(0, Math.min(1, Math.log1p(v) / Math.log1p(vmax)));
  const c = a.map((x, i) => Math.round(x + (b[i] - x) * k));
  return `rgb(${c.join(",")})`;
}
export function uptimeColor(u) {
  if (u == null) return cssVar("--surface-3");
  if (u >= 0.99) return cssVar("--good");
  if (u >= 0.9) return cssVar("--warning");
  if (u >= 0.5) return cssVar("--serious");
  return cssVar("--critical");
}
export function uptimeLabel(u) {
  if (u == null) return "pas de données";
  if (u >= 0.99) return "en ligne";
  if (u >= 0.9) return "coupures brèves";
  if (u >= 0.5) return "intermittent";
  return "hors ligne";
}

/**
 * Heatmap appareils × temps.
 * opts: { rows:[{label, sub, href}], t:[], values:[[]], mode:'latency'|'uptime', vmax, onRow }
 */
export function heatmap(container, opts) {
  const render = () => drawHeatmap(container, opts);
  render();
  autoResize(container, render);
}

function drawHeatmap(container, o) {
  container.classList.add("chart");
  container.querySelectorAll("svg").forEach((n) => n.remove());
  const W = Math.max(320, container.clientWidth);
  const labelW = Math.min(190, W * 0.34);
  const cellH = 22;
  const gap = 2;
  const top = 4;
  const H = top + o.rows.length * cellH + 24;
  const cols = o.t.length;
  const cw = (W - labelW - 4) / cols;
  const svg = el("svg", { width: W, height: H, role: "img", "aria-label": "heatmap" });
  container.appendChild(svg);
  const span = o.t[cols - 1] - o.t[0];

  o.rows.forEach((r, ri) => {
    const y = top + ri * cellH;
    const lbl = el("text", { x: 0, y: y + cellH / 2 + 4, class: "tick", style: "fill:var(--text-2);font-size:12px;cursor:pointer" }, svg);
    const txt = r.label.length > 24 ? r.label.slice(0, 23) + "…" : r.label;
    lbl.textContent = txt;
    if (o.onRow) lbl.addEventListener("click", () => o.onRow(ri));
    for (let ci = 0; ci < cols; ci++) {
      const v = o.values[ri][ci];
      let fill;
      if (o.mode === "uptime") fill = uptimeColor(v);
      else fill = v == null ? cssVar("--surface-3") : seqColor(v, o.vmax);
      const rect = el("rect", {
        x: labelW + ci * cw + gap / 2, y: y + gap / 2,
        width: Math.max(1, cw - gap), height: cellH - gap, rx: 3, fill,
        "data-r": ri, "data-c": ci,
      }, svg);
      if (v == null && o.mode !== "uptime" && o.up && o.up[ri][ci] === 0) {
        rect.setAttribute("fill", "none");
        rect.setAttribute("stroke", cssVar("--critical"));
        rect.setAttribute("stroke-opacity", "0.6");
      }
    }
  });
  const nx = Math.max(2, Math.min(8, Math.floor((W - labelW) / 80)));
  for (let i = 0; i <= nx; i++) {
    const ci = Math.round(((cols - 1) * i) / nx);
    el("text", {
      x: labelW + ci * cw + cw / 2, y: H - 6, class: "tick",
      "text-anchor": i === 0 ? "start" : i === nx ? "end" : "middle",
    }, svg).textContent = fmtTime(o.t[ci], span);
  }

  const tt = ensureTooltip(container);
  svg.addEventListener("mousemove", (ev) => {
    const target = ev.target;
    if (target.tagName !== "rect") return tt.classList.remove("show");
    const ri = +target.dataset.r;
    const ci = +target.dataset.c;
    const r = o.rows[ri];
    const v = o.values[ri][ci];
    const up = o.up ? o.up[ri][ci] : null;
    const valueTxt = o.mode === "uptime"
      ? v == null ? "pas de données" : `${(v * 100).toFixed(1)} % (${uptimeLabel(v)})`
      : v == null ? (up === 0 ? "hors ligne" : "pas de réponse ICMP") : fmtMs(v);
    tt.innerHTML = `<div class="tt-h">${fmtDateTime(o.t[ci])}</div>
      <div class="tt-r">${esc(r.label)}<b>${valueTxt}</b></div>
      ${r.sub ? `<div class="muted" style="font-size:11.5px">${esc(r.sub)}</div>` : ""}`;
    tt.classList.add("show");
    const cr = container.getBoundingClientRect();
    placeTooltip(tt, container, ev.clientX - cr.left, ev.clientY - cr.top);
  });
  svg.addEventListener("mouseleave", () => tt.classList.remove("show"));
  svg.addEventListener("click", (ev) => {
    if (ev.target.tagName === "rect" && o.onRow) o.onRow(+ev.target.dataset.r);
  });
}

/** Mini-courbe inline (chaîne SVG). */
export function sparkline(values, w = 96, h = 24) {
  const pts = values.map((v, i) => [i, v]).filter((p) => p[1] != null);
  if (pts.length < 2) return `<svg class="spark" width="${w}" height="${h}"></svg>`;
  const max = Math.max(...pts.map((p) => p[1])) || 1;
  const n = values.length - 1;
  const X = (i) => 1 + (i / n) * (w - 2);
  const Y = (v) => h - 2 - (v / max) * (h - 4);
  let d = "";
  let prev = -2;
  for (const [i, v] of pts) {
    d += (i === prev + 1 ? "L" : "M") + `${X(i).toFixed(1)},${Y(v).toFixed(1)}`;
    prev = i;
  }
  return `<svg class="spark" width="${w}" height="${h}" aria-hidden="true"><path d="${d}" fill="none" stroke="var(--s1)" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/></svg>`;
}

/** Bande de disponibilité (une case par pas de temps). */
export function uptimeStrip(container, t, up, maxCells = 96) {
  const n = t.length;
  const group = Math.max(1, Math.ceil(n / maxCells));
  let html = "";
  for (let i = 0; i < n; i += group) {
    const vals = up.slice(i, i + group).filter((v) => v != null);
    const v = vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
    const label = `${fmtDateTime(t[i])} — ${v == null ? "pas de données" : (v * 100).toFixed(1) + " % en ligne"}`;
    html += `<i style="background:${uptimeColor(v)}" title="${label}"></i>`;
  }
  container.className = "uptime-strip";
  container.innerHTML = html;
}
