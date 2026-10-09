"""Orchestration d'un diagnostic complet : lance les sondes actives (ping enrichi, traceroute,
MTU, DNS, bufferbloat), corrèle avec l'historique récent et produit constats + verdict.

Toutes les mesures réseau bloquantes passent par asyncio.to_thread pour ne pas figer la boucle.
"""
from __future__ import annotations

import asyncio
import logging
import time

from . import diagnostics as D
from . import icmp, probes

log = logging.getLogger("netwatch.diagrun")


async def _ping(hosts, count, timeout=1.0):
    if not hosts:
        return {}
    return await asyncio.to_thread(icmp.multiping, hosts, count, 0.2, timeout)


class DiagnosticRunner:
    def __init__(self, cfg, db, net):
        self.cfg = cfg
        self.db = db
        self.net = net

    async def run(self, trigger="manual", device_id=None):
        """Exécute un diagnostic et retourne (run_id, result, findings)."""
        t0 = time.time()
        run_id = self.db.x("INSERT INTO diag_runs(started, trigger, device_id) VALUES(?,?,?)",
                           [int(t0), trigger, device_id])
        try:
            result = await self._measure(device_id, trigger)
            result["duration"] = round(time.time() - t0, 2)
            findings = self._build_findings(result)
            verdict = D.latency_verdict(findings, result.get("correlation"),
                                        result.get("ext_high"))
            result["verdict"] = verdict
            self.db.update("diag_runs", run_id, {
                "finished": int(time.time()),
                "summary": verdict["summary"],
                "result_json": _json(result),
            })
            return run_id, result, findings
        except Exception:
            log.exception("Diagnostic en échec")
            self.db.update("diag_runs", run_id, {"finished": int(time.time()), "summary": "échec"})
            raise

    async def _measure(self, device_id, trigger):
        cfg, net = self.cfg, self.net
        gw = net.gateway
        ext = list(cfg.external_targets)
        result = {"gateway": gw, "trigger_device": device_id, "duration": None}

        # cible à diagnostiquer en priorité (appareil visé, sinon la 1re cible externe)
        focus = None
        if device_id:
            d = self.db.q1("SELECT ip FROM devices WHERE id=?", [device_id])
            focus = d["ip"] if d else None
        trace_target = focus or (ext[0] if ext else gw)

        ping_hosts = [h for h in ([gw] + ext + ([focus] if focus else [])) if h]
        ping_hosts = list(dict.fromkeys(ping_hosts))
        ping = await _ping(ping_hosts, cfg.diag_ping_count)
        result["ping"] = ping
        result["ext_high"] = {ip: ping[ip] for ip in ext
                              if ip in ping and (ping[ip].get("avg") or 0) > cfg.external_latency_warn_ms}

        gw_ok = bool(gw and ping.get(gw, {}).get("recv")
                     and (ping[gw].get("avg") or 99) < 10 and not ping[gw].get("loss"))
        result["gateway_ok"] = gw_ok

        # traceroute + MTU + DNS + santé locale en parallèle (chacun dans un thread)
        tasks = {
            "self": asyncio.to_thread(probes.self_health, net.interface),
        }
        if trace_target:
            tasks["traceroute"] = asyncio.to_thread(
                icmp.traceroute, probes.resolve_host(trace_target), 20, 3, 2.0)
            tasks["mtu"] = asyncio.to_thread(icmp.path_mtu, probes.resolve_host(trace_target))
        resolvers = list(dict.fromkeys(cfg.diag_dns_servers + probes.system_resolvers()))
        dns_tasks = [probes.dns_probe(s, cfg.diag_dns_domain) for s in resolvers[:4]]

        # TCP connect vers les cibles configurées (host:port)
        tcp_targets = []
        for spec in cfg.diag_tcp_targets:
            host, _, port = spec.partition(":")
            if host and port.isdigit():
                tcp_targets.append((host, int(port)))
        tcp_tasks = [probes.tcp_connect(h, p) for h, p in tcp_targets]

        gathered = await asyncio.gather(*tasks.values(), *dns_tasks, *tcp_tasks, return_exceptions=True)
        keys = list(tasks) + [f"dns::{r}" for r in resolvers[:4]] + [f"tcp::{h}:{p}" for h, p in tcp_targets]
        named = dict(zip(keys, gathered))

        def ok(v):
            return v if not isinstance(v, Exception) else None

        result["self"] = ok(named.get("self")) or {}
        result["traceroute"] = ok(named.get("traceroute"))
        result["mtu"] = ok(named.get("mtu"))
        result["dns"] = [ok(named[k]) for k in keys if k.startswith("dns::") and ok(named[k])]
        result["tcp"] = [ok(named[k]) for k in keys if k.startswith("tcp::") and ok(named[k])]

        # bufferbloat (optionnel, coûteux) : jamais sur un diagnostic déclenché par anomalie,
        # pour ne pas ajouter de charge alors que la latence est déjà mauvaise.
        if cfg.bufferbloat_url and trigger != "anomaly":
            bb_target = gw or (ext[0] if ext else None)
            if bb_target:
                result["bufferbloat"] = await asyncio.to_thread(
                    probes.bufferbloat, cfg.bufferbloat_url, bb_target, cfg.bufferbloat_seconds)

        result["correlation"] = self._correlate()
        return result

    def _correlate(self):
        """Corrèle les pics de latence des 15 dernières minutes entre appareils."""
        now = int(time.time())
        start = now - 15 * 60
        rows = self.db.q(
            "SELECT device_id, (ts/60)*60 AS m, AVG(latency) AS lat FROM samples "
            "WHERE ts >= ? AND latency IS NOT NULL GROUP BY device_id, m", [start])
        series = {}
        for r in rows:
            series.setdefault(r["device_id"], {})[r["m"]] = r["lat"]
        baselines = {}
        for r in self.db.q("SELECT id, baseline_latency FROM devices WHERE baseline_latency IS NOT NULL"):
            baselines[r["id"]] = r["baseline_latency"]
        if not series or not baselines:
            return None
        return D.correlate_spikes(series, baselines, self.cfg.anomaly_factor, self.cfg.anomaly_margin_ms)

    def _build_findings(self, r):
        cfg = self.cfg
        findings = []
        findings += D.scanner_findings(r.get("self") or {})
        findings += D.wan_findings(
            {ip: r["ping"][ip] for ip in cfg.external_targets if ip in r["ping"]},
            r["gateway_ok"], cfg.external_latency_warn_ms)
        if r.get("gateway"):
            findings += D.gateway_findings(r["ping"].get(r["gateway"]), cfg.latency_warn_ms)
        findings += D.dns_findings(r.get("dns") or [])
        findings += D.bufferbloat_findings(r.get("bufferbloat"))
        findings += D.mtu_findings(r.get("mtu"))
        tr = D.traceroute_analysis(r["traceroute"]) if r.get("traceroute") else None
        if tr:
            r["traceroute_analysis"] = tr
            seg = {"box": ("gateway", "sur la box"), "fai": ("wan", "chez le fournisseur d'accès"),
                   "transit": ("wan", "sur le transit Internet")}.get(tr["segment"], ("wan", ""))
            findings.append(D.finding(
                "traceroute", seg[0], "warning", f"Latence introduite au saut {tr['ttl']} {seg[1]}",
                f"La latence grimpe de {tr['increase']:.0f} ms au saut {tr['ttl']}"
                + (f" ({tr['ip']})" if tr.get("ip") else "") + " et reste élevée ensuite.",
                "Ce saut est le premier point de ralentissement le long du chemin.", tr))
        return findings


def _json(obj):
    import json
    return json.dumps(obj, default=str)
