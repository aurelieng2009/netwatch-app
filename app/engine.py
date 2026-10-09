"""Moteur : planification des scans, mise à jour de l'inventaire, événements, alertes."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time

from .box import BoxMonitor
from .backends import DemoBackend, RealBackend
from .config import Config
from .db import DB
from .diagrun import DiagnosticRunner
from .names import best_name, clean
from .netutil import OUIDB, NetInfo, is_random_mac, normalize_mac
from .notify import Notifier
from .push import PushManager
from .sshinv import SSHInventory
from .vault import Vault
from .z2m import Z2MMonitor

log = logging.getLogger("netwatch.engine")

# Garde-fous contre une inondation d'adresses MAC forgées : sans eux, chaque adresse créerait un
# appareil, un événement, une notification et un scan nmap.
MAX_NEW_PER_CYCLE = 25
MAX_DEVICES = 2048


def dev_label(d: dict) -> str:
    name = d.get("alias") or d.get("hostname") or d.get("vendor") or "Appareil inconnu"
    return f"{name} ({d.get('ip')})" if d.get("ip") and d.get("ip") != name else name


class Engine:
    def __init__(self, cfg: Config, db: DB):
        self.cfg = cfg
        self.db = db
        from . import settings as _settings
        _settings.load_overrides(cfg, db)  # réglages persistés depuis l'interface
        self.net = NetInfo(cfg.interface, cfg.subnet, cfg.exclude)
        self.oui = OUIDB()
        self.backend = DemoBackend(cfg, self.net) if cfg.demo else RealBackend(cfg, self.net)
        self.vault = Vault(db, cfg.secret_key, cfg.secret_key_path)
        self.push = PushManager(cfg, db, self.vault)
        self.notifier = Notifier(cfg, push=self.push)
        self.ssh = SSHInventory(cfg, db, self.vault, emit=self.emit)
        self.diag = DiagnosticRunner(cfg, db, self.net)
        self.box = BoxMonitor(cfg, db, self.vault, self.emit, gateway=lambda: self.net.gateway)
        self.z2m = Z2MMonitor(cfg, db, self.vault, self.emit)
        self._last_flood_alert = 0
        self.subscribers: set[asyncio.Queue] = set()
        self.deep_queue: asyncio.Queue[tuple[int, int | None]] = asyncio.Queue()
        self.deep_pending: set[int] = set()
        self.deep_batches: dict[int, dict] = {}
        self.name_sem = asyncio.Semaphore(16)
        self.ssh_sem = asyncio.Semaphore(8)
        self.tasks: list[asyncio.Task] = []
        self.diag_lock = asyncio.Lock()
        self._last_anomaly_diag = 0.0
        self._ip_last_mac: dict[str, tuple[str, int]] = {}   # ip -> (mac, ts) du dernier cycle
        self._ip_flaps: dict[str, set[str]] = {}             # ip -> MAC vues alterner récemment
        self._ha_published: set[str] = set()                 # macid déjà publiés en découverte HA
        self.status = {
            "started": int(time.time()),
            "discovery": {"running": False, "last": None, "duration": None, "next": None, "hosts": None},
            "deep": {"running": 0, "queued": 0, "last": None, "next": None},
            "diag": {"running": False, "last": None, "next": None},
            "ssh": {"enabled": self.ssh.enabled(), "locked": self.vault.locked, "reason": self.vault.reason},
        }
        self._discovery_lock = asyncio.Lock()

    # ----------------------------------------------------------- lifecycle
    async def start(self) -> None:
        if self.cfg.demo and not self.db.q1("SELECT id FROM devices LIMIT 1"):
            await asyncio.to_thread(self.backend.backfill, self.db, self.oui, self.cfg.external_targets)
        self._ensure_external_targets()
        log.info("Réseau : %s", self.net.as_dict())
        self.tasks = [
            asyncio.create_task(self._discovery_loop(), name="discovery"),
            asyncio.create_task(self._deep_scheduler(), name="deep-scheduler"),
            asyncio.create_task(self._maintenance_loop(), name="maintenance"),
            asyncio.create_task(self._diag_loop(), name="diag"),
            asyncio.create_task(self._box_loop(), name="box"),
            asyncio.create_task(self._z2m_loop(), name="z2m"),
            *[
                asyncio.create_task(self._deep_worker(i), name=f"deep-{i}")
                for i in range(max(1, self.cfg.nmap_concurrency))
            ],
        ]

    async def stop(self) -> None:
        for t in self.tasks:
            t.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        with contextlib.suppress(Exception):
            await asyncio.to_thread(self.box.close)    # ferme la session ouverte sur la box

    def _ensure_external_targets(self) -> None:
        now = int(time.time())
        for t in self.cfg.external_targets:
            if not self.db.q1("SELECT id FROM devices WHERE mac=?", [f"ext:{t}"]):
                self.db.x(
                    "INSERT INTO devices(mac, kind, ip, hostname, hostname_source, known, watch, first_seen, last_seen) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    [f"ext:{t}", "external", t, t, "config", 1, 1, now, now],
                )

    # ----------------------------------------------------------- pub/sub (SSE)
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)

    def broadcast(self, msg: dict) -> None:
        for q in list(self.subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass

    async def emit(self, type_: str, message: str, device: dict | None = None,
                   severity: str = "info", data: dict | None = None, notify: bool = True) -> None:
        ev = self.db.add_event(type_, message, device["id"] if device else None, severity, data)
        log.info("[%s] %s", type_, message)
        self.broadcast({"type": "event", "event": ev})
        if notify and self.notifier.enabled:
            asyncio.create_task(self.notifier.event(ev, device))

    # ----------------------------------------------------------- discovery
    async def _discovery_loop(self) -> None:
        while True:
            start = time.monotonic()
            try:
                if self.cfg.scans_enabled:
                    await self.discovery_cycle()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("Cycle de découverte en échec")
            delay = max(5.0, self.cfg.discovery_interval - (time.monotonic() - start))
            self.status["discovery"]["next"] = int(time.time() + delay)
            await asyncio.sleep(delay)

    async def discovery_cycle(self) -> None:
        async with self._discovery_lock:
            await self._discovery_cycle()

    def _refresh_excluded(self) -> None:
        """Recharge les IP exclues par appareil pour que discover() les écarte dès ce cycle."""
        self.net.extra_excluded = {
            r["ip"] for r in self.db.q("SELECT ip FROM devices WHERE excluded=1 AND ip IS NOT NULL")
        }

    async def _discovery_cycle(self) -> None:
        st = self.status["discovery"]
        st["running"] = True
        t0 = time.monotonic()
        now = int(time.time())
        self._refresh_excluded()
        scan_id = self.db.x("INSERT INTO scans(type, started) VALUES('discovery', ?)", [now])
        try:
            found = await self.backend.discover()  # {ip: (mac, rtt)}
            if self.net.ip and self.net.mac and self.net.ip not in found and not self.cfg.demo:
                found[self.net.ip] = (self.net.mac, 0.0)  # la machine elle-même
            ext = self.cfg.external_targets
            pings = await self.backend.ping(list(found.keys()) + ext)

            devices = {d["mac"]: d for d in self.db.q("SELECT * FROM devices WHERE kind='lan'")}
            initial = not devices  # premier inventaire : pas de rafale de notifications
            seen_ids: set[int] = set()
            samples: list[tuple] = []
            new_devices: list[dict] = []
            flood = 0

            for ip, (mac, arp_rtt) in found.items():
                mac = normalize_mac(mac)
                p = pings.get(ip) or {}
                latency = p.get("avg")
                loss = p.get("loss") if p.get("recv") else (100.0 if p else None)
                d = devices.get(mac)
                if d is None and ((not initial and len(new_devices) >= MAX_NEW_PER_CYCLE) or len(devices) >= MAX_DEVICES):
                    flood += 1          # inondation d'adresses MAC : on n'enregistre pas tout ce qui passe
                    continue
                if d is None:
                    vendor = self.oui.lookup(mac)
                    did = self.db.x(
                        """INSERT INTO devices(mac, kind, ip, vendor, random_mac, online, missed,
                           first_seen, last_seen, last_latency, last_loss)
                           VALUES(?,?,?,?,?,1,0,?,?,?,?)""",
                        [mac, "lan", ip, vendor, int(is_random_mac(mac)), now, now, latency, loss],
                    )
                    d = self.db.q1("SELECT * FROM devices WHERE id=?", [did])
                    devices[mac] = d
                    new_devices.append(d)
                    extra = " — MAC aléatoire (appareil mobile probable)" if d["random_mac"] else ""
                    await self.emit(
                        "new_device",
                        f"Nouvel appareil : {ip} [{mac}] {vendor or 'constructeur inconnu'}{extra}",
                        d, "info" if initial else "warning", {"ip": ip, "mac": mac, "vendor": vendor},
                        notify=not initial,
                    )
                else:
                    upd = {"online": 1, "missed": 0, "last_seen": now, "last_latency": latency, "last_loss": loss}
                    if d["ip"] != ip:
                        upd["ip"] = ip
                        await self.emit(
                            "ip_changed", f"{dev_label(d)} : IP {d['ip']} → {ip}", d, "info",
                            {"old": d["ip"], "new": ip}, notify=bool(d["watch"]),
                        )
                    if not d["online"]:
                        await self.emit(
                            "device_online", f"{dev_label({**d, 'ip': ip})} est de retour en ligne", d, "info",
                            notify=bool(d["watch"]),
                        )
                    self.db.update("devices", d["id"], upd)
                    d.update(upd)
                seen_ids.add(d["id"])
                samples.append((d["id"], now, 1, latency, loss if loss is not None else 0.0, p.get("jitter")))

            if flood and now - self._last_flood_alert > 3600:
                self._last_flood_alert = now
                await self.emit(
                    "security_finding",
                    f"{flood} adresses MAC inconnues ignorées en un seul cycle : inondation ou usurpation probable "
                    f"(au plus {MAX_NEW_PER_CYCLE} nouveaux appareils par cycle, {MAX_DEVICES} au total).",
                    None, "critical", {"ignored": flood})

            # appareils non vus
            for d in devices.values():
                if d["id"] in seen_ids:
                    continue
                if d["excluded"]:
                    # exclu : ni alerte hors ligne, ni échantillon « down »
                    if d["online"]:
                        self.db.update("devices", d["id"], {"online": 0})
                    continue
                if d["online"]:
                    missed = d["missed"] + 1
                    upd = {"missed": missed}
                    if missed >= self.cfg.offline_after:
                        upd["online"] = 0
                        await self.emit(
                            "device_offline", f"{dev_label(d)} est hors ligne", d,
                            "warning" if d["watch"] else "info", notify=bool(d["watch"]),
                        )
                    self.db.update("devices", d["id"], upd)
                    d.update(upd)
                # échantillon « down » pour les appareils vus dans les dernières 24 h ou surveillés
                if d["watch"] or (d["last_seen"] or 0) > now - 86400:
                    samples.append((d["id"], now, 0, None, 100.0, None))

            # cibles externes
            for t in ext:
                d = self.db.q1("SELECT * FROM devices WHERE mac=?", [f"ext:{t}"])
                if not d:
                    continue
                p = pings.get(t) or {}
                up = bool(p.get("recv"))
                upd = {"last_latency": p.get("avg"), "last_loss": p.get("loss")}
                if up:
                    upd.update(online=1, missed=0, last_seen=now)
                    if d["missed"] >= 2:
                        await self.emit("device_online", f"Cible Internet {t} de nouveau joignable", d, "info")
                else:
                    upd["missed"] = d["missed"] + 1
                    if upd["missed"] == 2:
                        upd["online"] = 0
                        await self.emit("device_offline", f"Cible Internet {t} injoignable", d, "critical")
                self.db.update("devices", d["id"], upd)
                samples.append((d["id"], now, int(up), p.get("avg"), p.get("loss"), p.get("jitter")))

            self.db.xmany(
                "INSERT INTO samples(device_id, ts, up, latency, loss, jitter) VALUES(?,?,?,?,?,?)", samples)
            await self._check_conflicts(found, now)
            await self._check_gateway_mac(found)
            if initial and new_devices:
                await self.emit(
                    "inventory", f"Inventaire initial : {len(new_devices)} appareils découverts sur {self.net.network}",
                    None, "info", {"count": len(new_devices)},
                )

            lan_lat = [s[3] for s in samples if s[3] is not None and s[0] in seen_ids]
            total = self.db.q1(
                "SELECT COUNT(*) AS n FROM devices WHERE kind='lan' AND (last_seen > ? OR watch=1)",
                [now - 86400],
            )["n"]
            self.db.x(
                "INSERT OR REPLACE INTO net_samples(ts, online, total, avg_latency) VALUES(?,?,?,?)",
                [now, len(seen_ids), total, round(sum(lan_lat) / len(lan_lat), 2) if lan_lat else None],
            )

            await self._check_latency_alerts(now)
            await self._update_baselines(now, seen_ids)

            duration = round(time.monotonic() - t0, 2)
            self.db.update("scans", scan_id, {
                "finished": int(time.time()), "hosts": len(seen_ids),
                "detail": json.dumps({"duration": duration, "new": len(new_devices)}),
            })
            st.update({"last": now, "duration": duration, "hosts": len(seen_ids)})
            self.broadcast({"type": "discovery", "ts": now, "hosts": len(seen_ids), "duration": duration})

            # noms d'hôtes : nouveaux appareils + rafraîchissement périodique
            stale = self.db.q(
                "SELECT * FROM devices WHERE kind='lan' AND online=1 AND alias IS NULL AND "
                "(last_name_check IS NULL OR last_name_check < ?)",
                [now - self.cfg.name_refresh_interval],
            )
            for d in stale:
                asyncio.create_task(self._resolve_name(d))
            # scan approfondi pour les nouveaux venus
            if new_devices and not initial and self.cfg.scans_enabled:  # l'inventaire initial est couvert par le planificateur
                await self.enqueue_deep([d["id"] for d in new_devices])

            if self.notifier.cfg.mqtt_host:
                asyncio.create_task(self.notifier.device_states(
                    self.db.q("SELECT * FROM devices WHERE kind='lan' AND (online=1 OR watch=1)")
                ))
                self._sync_ha_discovery()
        finally:
            st["running"] = False

    async def _resolve_name(self, d: dict) -> None:
        async with self.name_sem:
            try:
                found = await self.backend.resolve(d["ip"])
            except Exception as e:  # noqa: BLE001
                log.debug("résolution %s: %s", d["ip"], e)
                found = {}
            cur = self.db.q1("SELECT names_json FROM devices WHERE id=?", [d["id"]])
            names = json.loads(cur["names_json"]) if cur and cur["names_json"] else {}
            names.update({k: clean(v) for k, v in found.items()})
            host, src = best_name(names)
            fields = {"names_json": json.dumps(names), "last_name_check": int(time.time())}
            if host:
                fields.update({"hostname": host, "hostname_source": src})
            self.db.update("devices", d["id"], fields)
            if host and host != d.get("hostname"):
                self.broadcast({"type": "device", "id": d["id"]})

    async def _check_latency_alerts(self, now: int) -> None:
        rows = self.db.q(
            """SELECT d.*, AVG(s.latency) AS lat5, AVG(s.loss) AS loss5, COUNT(s.ts) AS n
               FROM devices d JOIN samples s ON s.device_id = d.id AND s.ts > ?
               WHERE (d.watch = 1 OR d.kind = 'external') AND d.online = 1
               GROUP BY d.id""",
            [now - 5 * 60 - 5],
        )
        for d in rows:
            if d["n"] < 3:
                continue
            thr = self.cfg.external_latency_warn_ms if d["kind"] == "external" else self.cfg.latency_warn_ms
            lat, loss = d["lat5"], d["loss5"] or 0
            high = (lat is not None and lat > thr) or loss > self.cfg.loss_warn_pct
            ok = (lat is None or lat < thr * 0.7) and loss < self.cfg.loss_warn_pct / 2
            if high and d["alert_state"] != "high":
                self.db.update("devices", d["id"], {"alert_state": "high"})
                msg = f"{dev_label(d)} : latence moyenne {lat:.0f} ms, perte {loss:.0f} % (5 min)" if lat else \
                      f"{dev_label(d)} : perte de paquets {loss:.0f} % (5 min)"
                await self.emit("high_latency", msg, d, "warning", {"latency": lat, "loss": loss})
            elif ok and d["alert_state"] == "high":
                self.db.update("devices", d["id"], {"alert_state": None})
                await self.emit(
                    "latency_ok", f"{dev_label(d)} : latence revenue à la normale ({(lat or 0):.0f} ms)", d, "info",
                )

    # ----------------------------------------------------------- conflits d'IP
    async def _check_conflicts(self, found: dict, now: int) -> None:
        """Deux sources : plusieurs MAC ayant répondu à l'ARP pour une même IP (conflit direct
        ou usurpation), et une IP qui « saute » entre plusieurs MAC en peu de temps (bail DHCP
        en collision). Un conflit reste actif tant qu'il est revu dans la fenêtre configurée."""
        conflicts = dict(getattr(self.backend, "last_conflicts", {}) or {})

        # IP qui change de MAC d'un cycle à l'autre, plusieurs fois dans la fenêtre
        window = self.cfg.conflict_window
        for ip, (mac, _rtt) in found.items():
            mac = normalize_mac(mac)
            prev = self._ip_last_mac.get(ip)
            self._ip_last_mac[ip] = (mac, now)
            if prev and prev[0] != mac and now - prev[1] < window:
                self._ip_flaps.setdefault(ip, set()).update({prev[0], mac})
        for ip in list(self._ip_flaps):
            last = self._ip_last_mac.get(ip)
            if not last or now - last[1] > window:
                self._ip_flaps.pop(ip, None)
            elif len(self._ip_flaps[ip]) > 1:
                conflicts.setdefault(ip, set()).update(self._ip_flaps[ip])

        for ip, macs in conflicts.items():
            macs = {normalize_mac(m) for m in macs}
            if len(macs) < 2:
                continue
            source = "arp_multi" if ip in getattr(self.backend, "last_conflicts", {}) else "flapping"
            row = self.db.q1("SELECT * FROM ip_conflicts WHERE ip=? AND resolved=0", [ip])
            macs_json = json.dumps(sorted(macs))
            if row:
                self.db.update("ip_conflicts", row["id"],
                               {"last_seen": now, "occurrences": row["occurrences"] + 1, "macs_json": macs_json})
            else:
                self.db.x(
                    "INSERT INTO ip_conflicts(ip, macs_json, source, first_seen, last_seen) VALUES(?,?,?,?,?)",
                    [ip, macs_json, source, now, now])
                vendors = ", ".join(sorted(self.oui.lookup(m) or m for m in macs))
                await self.emit(
                    "ip_conflict",
                    f"Conflit d'IP : {ip} revendiquée par {len(macs)} MAC ({vendors})",
                    None, "critical", {"ip": ip, "macs": sorted(macs), "source": source})

        # résolution : conflit non revu au-delà de 2 fenêtres
        for row in self.db.q("SELECT * FROM ip_conflicts WHERE resolved=0 AND last_seen < ?",
                             [now - 2 * window]):
            self.db.update("ip_conflicts", row["id"], {"resolved": 1})

    def apply_settings_side_effects(self, applied: dict) -> None:
        """Réactions immédiates à un changement de réglage (hors valeurs relues à chaque cycle)."""
        from .netutil import parse_nets
        if "exclude" in applied:
            self.net.exclude_nets = parse_nets(self.cfg.exclude)
        if "external_targets" in applied:
            self._ensure_external_targets()

    def _sync_ha_discovery(self) -> None:
        """Publie/retire les entités Home Assistant selon les appareils surveillés."""
        if not (self.cfg.mqtt_host and self.cfg.mqtt_discovery):
            return
        watched = {d["mac"].replace(":", ""): d
                   for d in self.db.q("SELECT * FROM devices WHERE kind='lan' AND watch=1")}
        new = [d for mid, d in watched.items() if mid not in self._ha_published]
        gone = [mid for mid in self._ha_published if mid not in watched]
        if new:
            asyncio.create_task(self.notifier.ha_discovery(new))
        if gone:
            asyncio.create_task(self.notifier.ha_remove(gone))
        self._ha_published = set(watched)

    async def _check_gateway_mac(self, found: dict) -> None:
        """Épingle la MAC de la passerelle ; un changement = routeur remplacé ou usurpation ARP."""
        gw = self.net.gateway
        if not gw or gw not in found:
            return
        mac = normalize_mac(found[gw][0])
        if not mac:
            return
        prev = self.db.get_meta("gateway_mac")
        if prev and prev != mac:
            d = self.db.q1("SELECT * FROM devices WHERE ip=? AND kind='lan'", [gw])
            await self.emit(
                "gateway_mac_changed",
                f"La MAC de la passerelle {gw} a changé ({prev} → {mac}). Routeur remplacé, "
                "ou possible usurpation ARP.", d, "critical", {"ip": gw, "old": prev, "new": mac})
        if prev != mac:
            self.db.set_meta("gateway_mac", mac)

    async def _check_rogue_dhcp(self) -> None:
        """Sonde DHCP : plusieurs serveurs qui répondent = serveur pirate."""
        if self.cfg.demo or not self.net.mac:
            return
        from . import dhcp
        servers = await asyncio.to_thread(dhcp.discover_servers, self.net.interface, self.net.mac)
        if servers is None:
            return  # sonde indisponible (port 68 occupé)
        now = int(time.time())
        self.db.set_meta("dhcp_last_check", str(now))
        self.db.set_meta("dhcp_servers", json.dumps([s["server"] for s in servers]))
        expected = self.db.get_meta("dhcp_expected")
        if not expected and len(servers) == 1:
            self.db.set_meta("dhcp_expected", servers[0]["server"])  # 1er vu = référence
            expected = servers[0]["server"]
        ids = sorted(s["server"] for s in servers if s.get("server"))
        findings = []
        if len(ids) > 1:
            findings.append({
                "key": "sec:dhcp:multi", "category": "security", "severity": "critical",
                "title": "Plusieurs serveurs DHCP sur le réseau",
                "detail": f"{len(ids)} serveurs DHCP répondent : {', '.join(ids)}. "
                          "Un seul est normalement attendu (ta box).",
                "suggestion": "Repère le serveur en trop (routeur ajouté, point d'accès mal configuré) "
                              "et désactive son DHCP.",
                "evidence": {"servers": ids}, "device_id": None})
        elif expected and ids and ids != [expected]:
            findings.append({
                "key": "sec:dhcp:changed", "category": "security", "severity": "warning",
                "title": "Serveur DHCP différent de d'habitude",
                "detail": f"Le DHCP répond depuis {ids[0]} (attendu : {expected}).",
                "suggestion": "Vérifie quel équipement distribue les adresses IP.",
                "evidence": {"servers": ids, "expected": expected}, "device_id": None})
        created = await self._apply_findings(findings, None, deactivate_like="sec:dhcp:%")
        for f in created:
            await self.emit("rogue_dhcp", f"{f['title']} — {f['detail']}", None, f["severity"],
                            {"key": f["key"]}, notify=True)

    # ----------------------------------------------------------- latence de référence + anomalies
    async def _update_baselines(self, now: int, seen_ids: set[int]) -> None:
        """Référence = médiane robuste (p25) de la latence sur 7 jours ; recalculée toutes les 6 h.
        Une anomalie = latence 5 min très au-dessus de la référence pour un appareil surveillé."""
        if now - int(self.db.get_meta("baseline_at", "0") or 0) > 6 * 3600:
            rows = self.db.q(
                "SELECT device_id, latency FROM samples WHERE ts > ? AND latency IS NOT NULL",
                [now - 7 * 86400])
            by_dev: dict[int, list[float]] = {}
            for r in rows:
                by_dev.setdefault(r["device_id"], []).append(r["latency"])
            from .icmp import percentile
            for did, vals in by_dev.items():
                if len(vals) >= 20:
                    self.db.update("devices", did,
                                   {"baseline_latency": percentile(vals, 25),
                                    "baseline_jitter": percentile(vals, 50)})
            self.db.set_meta("baseline_at", str(now))

        rows = self.db.q(
            """SELECT d.*, AVG(s.latency) AS lat5, COUNT(s.latency) AS n
               FROM devices d
               JOIN samples s ON s.device_id=d.id AND s.ts > ? AND s.latency IS NOT NULL
               WHERE d.baseline_latency IS NOT NULL AND (d.watch=1 OR d.kind='external')
               GROUP BY d.id""",
            [now - 5 * 60 - 5])
        anomalous = 0
        for d in rows:
            if d["n"] < 3:
                continue
            thr = max(d["baseline_latency"] * self.cfg.anomaly_factor,
                      d["baseline_latency"] + self.cfg.anomaly_margin_ms)
            if d["lat5"] > thr and d["anomaly_state"] != "anomaly":
                self.db.update("devices", d["id"], {"anomaly_state": "anomaly"})
                anomalous += 1
                await self.emit(
                    "latency_anomaly",
                    f"{dev_label(d)} : latence {d['lat5']:.0f} ms, très au-dessus de sa normale "
                    f"({d['baseline_latency']:.0f} ms)", d, "warning",
                    {"latency": round(d["lat5"], 1), "baseline": round(d["baseline_latency"], 1)})
            elif d["lat5"] < thr * 0.8 and d["anomaly_state"] == "anomaly":
                self.db.update("devices", d["id"], {"anomaly_state": None})

        # anomalie généralisée → déclenche un diagnostic ciblé (avec anti-rebond)
        if anomalous >= 2 and self.cfg.diag_enabled and time.time() - self._last_anomaly_diag > self.cfg.diag_trigger_cooldown:
            self._last_anomaly_diag = time.time()
            asyncio.create_task(self.run_diagnostic("anomaly"))

    # ----------------------------------------------------------- deep scan
    async def enqueue_deep(self, device_ids: list[int], batch_type: str = "deep") -> int | None:
        ids = [i for i in device_ids if i not in self.deep_pending]
        if not ids:
            return None
        scan_id = self.db.x("INSERT INTO scans(type, started, hosts) VALUES(?, ?, ?)",
                            [batch_type, int(time.time()), len(ids)])
        self.deep_batches[scan_id] = {"remaining": len(ids), "t0": time.monotonic(), "ports": 0}
        for i in ids:
            self.deep_pending.add(i)
            await self.deep_queue.put((i, scan_id))
        self.status["deep"]["queued"] = self.deep_queue.qsize()
        self.broadcast({"type": "deep", "queued": self.deep_queue.qsize(), "running": self.status["deep"]["running"]})
        return scan_id

    async def _deep_scheduler(self) -> None:
        # premier passage 2 minutes après le démarrage (le temps d'une découverte)
        last = int(self.db.get_meta("last_deep_batch", "0") or 0)
        wait = max(120, last + self.cfg.deep_interval - time.time())
        while True:
            self.status["deep"]["next"] = int(time.time() + wait)
            await asyncio.sleep(wait)
            if not self.cfg.scans_enabled or not self.cfg.deep_enabled:
                wait = 60
                continue
            ids = [r["id"] for r in self.db.q("SELECT id FROM devices WHERE kind='lan' AND online=1")]
            log.info("Scan approfondi planifié : %d appareils", len(ids))
            await self.enqueue_deep(ids)
            self.db.set_meta("last_deep_batch", str(int(time.time())))
            wait = self.cfg.deep_interval

    async def _deep_worker(self, n: int) -> None:
        while True:
            did, scan_id = await self.deep_queue.get()
            self.status["deep"]["running"] += 1
            self.status["deep"]["queued"] = self.deep_queue.qsize()
            try:
                await self._deep_one(did, scan_id)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("Scan approfondi %s en échec", did)
            finally:
                self.deep_pending.discard(did)
                self.status["deep"]["running"] -= 1
                b = self.deep_batches.get(scan_id)
                if b:
                    b["remaining"] -= 1
                    if b["remaining"] <= 0:
                        self.db.update("scans", scan_id, {
                            "finished": int(time.time()),
                            "detail": json.dumps({"duration": round(time.monotonic() - b["t0"], 1),
                                                  "open_ports": b["ports"]}),
                        })
                        self.status["deep"]["last"] = int(time.time())
                        del self.deep_batches[scan_id]
                self.broadcast({"type": "deep", "queued": self.deep_queue.qsize(),
                                "running": self.status["deep"]["running"], "device": did})
                self.deep_queue.task_done()

    async def _deep_one(self, did: int, scan_id: int | None) -> None:
        d = self.db.q1("SELECT * FROM devices WHERE id=?", [did])
        if not d or not d["ip"] or d["kind"] != "lan":
            return
        if self.net.is_excluded(d["ip"]):
            log.debug("nmap ignoré : %s est exclu", d["ip"])
            return
        res = await self.backend.deep_scan(d["ip"])
        if res is None:
            return
        now = int(time.time())
        fields: dict = {"last_deep_scan": now}
        if res.get("os"):
            fields["os_name"], fields["os_accuracy"] = res["os"]
        if res.get("hostname"):
            names = json.loads(d["names_json"]) if d["names_json"] else {}
            names["nmap"] = clean(res["hostname"])
            fields["names_json"] = json.dumps(names)
            if not d["hostname"]:
                fields["hostname"], fields["hostname_source"] = best_name(names)
        if res.get("vendor") and not d["vendor"]:
            fields["vendor"] = res["vendor"]
        self.db.update("devices", did, fields)

        if res.get("down"):
            log.info("nmap : %s ne répond pas, ports inchangés", d["ip"])
            return
        first_scan = d["last_deep_scan"] is None
        existing = {(p["port"], p["proto"]): p for p in self.db.q(
            "SELECT * FROM ports WHERE device_id=? AND open=1", [did])}
        current = {(p["port"], p["proto"]): p for p in res["ports"]}
        if scan_id in self.deep_batches:
            self.deep_batches[scan_id]["ports"] += len(current)
        rows = []
        for key, p in current.items():
            rows.append((did, p["port"], p["proto"], p["service"], p["product"], p["version"], p["extra"], now, now))
        self.db.xmany(
            """INSERT INTO ports(device_id, port, proto, service, product, version, extra, open, first_seen, last_seen)
               VALUES(?,?,?,?,?,?,?,1,?,?)
               ON CONFLICT(device_id, port, proto) DO UPDATE SET
                 service=excluded.service, product=excluded.product, version=excluded.version,
                 extra=excluded.extra, open=1, last_seen=excluded.last_seen""",
            rows,
        )
        label = dev_label(d)
        for key in current.keys() - existing.keys():
            if first_scan:
                continue
            p = current[key]
            what = " ".join(x for x in (p["product"] or p["service"], p["version"]) if x)
            await self.emit("port_opened", f"{label} : port {key[0]}/{key[1]} ouvert{f' ({what})' if what else ''}",
                            d, "warning", {"port": key[0], "proto": key[1]})
        for key in existing.keys() - current.keys():
            self.db.x("UPDATE ports SET open=0 WHERE device_id=? AND port=? AND proto=?", [did, *key])
            await self.emit("port_closed", f"{label} : port {key[0]}/{key[1]} fermé", d, "info",
                            {"port": key[0], "proto": key[1]}, notify=bool(d["watch"]))
        self.broadcast({"type": "device", "id": did})

        # analyse d'exposition (ports en clair, bases ouvertes, versions anciennes)
        try:
            await self._analyze_security(self.db.q1("SELECT * FROM devices WHERE id=?", [did]))
        except Exception:  # noqa: BLE001
            log.exception("Analyse sécurité %s en échec", did)

        # inventaire SSH authentifié après le scan de ports (les ports ouverts guident le choix)
        if not self.cfg.demo and self.ssh.enabled() and d["kind"] == "lan" and not res.get("down"):
            asyncio.create_task(self._ssh_one(did))

    async def _ssh_one(self, did: int) -> None:
        async with self.ssh_sem:
            d = self.db.q1("SELECT * FROM devices WHERE id=?", [did])
            if not d or not d["ip"] or self.net.is_excluded(d["ip"]):
                return
            try:
                res = await self.ssh.collect_device(d)
            except Exception:  # noqa: BLE001
                log.exception("Inventaire SSH %s en échec", d["ip"])
                return
            if res:
                self.broadcast({"type": "device", "id": did})

    # ----------------------------------------------------------- diagnostic de latence
    async def _diag_loop(self) -> None:
        last = int(self.db.get_meta("last_diag", "0") or 0)
        wait = max(180, last + self.cfg.diag_interval - time.time())
        while True:
            self.status["diag"]["next"] = int(time.time() + wait)
            await asyncio.sleep(wait)
            if not self.cfg.diag_enabled:
                wait = 60
                continue
            try:
                await self.run_diagnostic("scheduled")
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("Diagnostic planifié en échec")
            wait = self.cfg.diag_interval

    async def run_diagnostic(self, trigger: str = "manual", device_id: int | None = None) -> dict | None:
        """Lance un diagnostic complet, enregistre les constats et émet un résumé.
        Un seul diagnostic à la fois (verrou)."""
        if self.cfg.demo:
            return None
        if self.diag_lock.locked() and trigger != "manual":
            return None
        async with self.diag_lock:
            self.status["diag"]["running"] = True
            self.broadcast({"type": "diag", "running": True})
            try:
                run_id, result, findings = await self.diag.run(trigger, device_id)
            finally:
                self.status["diag"]["running"] = False
                self.status["diag"]["last"] = int(time.time())
                self.db.set_meta("last_diag", str(int(time.time())))
            await self._apply_findings(findings, run_id)
            verdict = result.get("verdict", {})
            await self.emit(
                "diag_finding",
                f"Diagnostic ({trigger}) : {verdict.get('summary', 'terminé')}",
                None, verdict.get("severity", "info"),
                {"run_id": run_id, "origin": verdict.get("origin"), "findings": len(findings)},
                notify=bool(findings) and verdict.get("severity") != "info")
            self.broadcast({"type": "diag", "running": False, "run_id": run_id})
            return result

    async def _apply_findings(self, findings: list[dict], run_id: int | None,
                              deactivate_like: str = "net:%",
                              deactivate_extra: str = "") -> list[dict]:
        """Insère/rafraîchit les constats et désactive ceux (du même périmètre) non revus.
        Retourne les constats nouvellement créés (pour émettre un événement au besoin)."""
        now = int(time.time())
        seen_keys = set()
        created: list[dict] = []
        for f in findings:
            seen_keys.add(f["key"])
            row = self.db.q1("SELECT * FROM findings WHERE key=?", [f["key"]])
            if row:
                self.db.update("findings", row["id"], {
                    "severity": f["severity"], "title": f["title"], "detail": f["detail"],
                    "suggestion": f["suggestion"], "evidence_json": json.dumps(f["evidence"], default=str),
                    "last_seen": now, "active": 1, "run_id": run_id, "device_id": f["device_id"]})
            else:
                self.db.x(
                    """INSERT INTO findings(key, category, severity, title, detail, suggestion,
                       evidence_json, device_id, first_seen, last_seen, active, run_id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,1,?)""",
                    [f["key"], f["category"], f["severity"], f["title"], f["detail"], f["suggestion"],
                     json.dumps(f["evidence"], default=str), f["device_id"], now, now, run_id])
                created.append(f)
        # constats du même périmètre non revus -> désactivés
        sql = f"SELECT id, key FROM findings WHERE active=1 AND key LIKE '{deactivate_like}'{deactivate_extra}"
        for row in self.db.q(sql):
            if row["key"] not in seen_keys:
                self.db.update("findings", row["id"], {"active": 0})
        return created

    async def _analyze_security(self, device: dict) -> None:
        """Constats de sécurité pour un appareil, à partir de ses ports ouverts."""
        from . import security
        ports = self.db.q("SELECT * FROM ports WHERE device_id=? AND open=1", [device["id"]])
        findings = security.analyze(device, ports)
        created = await self._apply_findings(
            findings, None, deactivate_like=f"sec:{device['id']}:%")
        for f in created:
            if f["severity"] in ("warning", "critical"):
                await self.emit("security_finding", f"{f['title']} — {f['detail']}",
                                device, f["severity"], {"key": f["key"]}, notify=True)

    # ----------------------------------------------------------- maintenance
    async def _box_loop(self) -> None:
        if self.cfg.demo:
            return
        while True:
            try:
                if self.cfg.box_enabled:
                    await self.box.poll()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("Cycle box en échec")
            await asyncio.sleep(max(15, self.cfg.box_interval))

    async def _z2m_loop(self) -> None:
        if self.cfg.demo:
            return
        try:
            await self.z2m.run()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("Écoute Zigbee2MQTT interrompue")

    async def _maintenance_loop(self) -> None:
        last_purge = 0.0
        last_dhcp = 0.0
        while True:
            await asyncio.sleep(300)
            try:
                await asyncio.to_thread(self.db.rollup_hourly)
                if time.time() - last_purge > 3600:
                    await asyncio.to_thread(
                        self.db.purge, self.cfg.raw_retention_days,
                        self.cfg.hourly_retention_days, self.cfg.event_retention_days,
                    )
                    last_purge = time.time()
                if time.time() - last_dhcp > 3600:
                    await self._check_rogue_dhcp()
                    last_dhcp = time.time()
            except Exception:  # noqa: BLE001
                log.exception("Maintenance en échec")
