"""Backends de scan : réel (réseau) et démo (simulation pour tester l'UI)."""
from __future__ import annotations

import asyncio
import logging
import math
import random
import time

from . import arp, icmp, names, nmapscan
from .config import Config
from .netutil import NetInfo

log = logging.getLogger("netwatch.backend")


class RealBackend:
    def __init__(self, cfg: Config, net: NetInfo):
        self.cfg = cfg
        self.net = net
        self.arp_mode = "arp"
        self.last_conflicts: dict[str, set[str]] = {}  # {ip: {mac, ...}} avec > 1 MAC

    async def discover(self) -> dict[str, tuple[str, float | None]]:
        """Retourne {ip: (mac, rtt_arp_ms)} des hôtes présents sur le LAN.
        Renseigne self.last_conflicts avec les IP ayant répondu depuis plusieurs MAC."""
        self.last_conflicts = {}
        hosts = self.net.hosts()
        if not hosts:
            return {}
        if self.arp_mode == "arp" and self.net.ip and self.net.mac:
            try:
                seen: dict[str, set[str]] = {}
                res = await asyncio.to_thread(
                    arp.arp_scan, self.net.interface, self.net.mac, self.net.ip, hosts,
                    self.cfg.arp_timeout, self.cfg.arp_retries, 0.002, seen,
                )
                self.last_conflicts = {ip: macs for ip, macs in seen.items() if len(macs) > 1}
                return res
            except PermissionError:
                log.warning(
                    "Scan ARP impossible (CAP_NET_RAW manquante ?) : repli sur ping + cache ARP"
                )
                self.arp_mode = "ping"
            except OSError as e:
                log.warning("Scan ARP en échec (%s) : repli sur ping + cache ARP", e)
                self.arp_mode = "ping"
        # repli : balayage ICMP puis lecture du cache ARP du noyau
        res = await asyncio.to_thread(icmp.multiping, hosts, 1, 0.05, 1.0)
        cache = arp.read_arp_cache(self.net.interface)
        out = {}
        for ip, mac in cache.items():
            if ip in res and res[ip]["recv"]:
                out[ip] = (mac, None)
        return out

    async def ping(self, ips: list[str]) -> dict[str, dict]:
        return await asyncio.to_thread(
            icmp.multiping, ips, self.cfg.ping_count, 0.25, self.cfg.ping_timeout
        )

    async def resolve(self, ip: str) -> dict[str, str]:
        return await names.resolve_all(ip)

    async def deep_scan(self, ip: str) -> dict | None:
        if not nmapscan.nmap_available():
            log.error("nmap n'est pas installé : scan approfondi désactivé")
            return None
        return await nmapscan.scan_host(ip, self.cfg.nmap_args)


# ---------------------------------------------------------------------- DEMO
DEMO_DEVICES = [
    # (suffixe IP, mac, nom, vendeur, type, latence de base ms, ports)
    (1, "f4:ca:e5:10:20:01", "freebox-server", "Freebox SAS", "router", 0.6, [(53, "domain", "dnsmasq", "2.89"), (80, "http", "nginx", None), (443, "https", "nginx", None)]),
    (2, "68:d7:9a:31:aa:02", "switch-salon", "Ubiquiti", "switch", 0.9, [(22, "ssh", "Dropbear sshd", "2020.81"), (443, "https", None, None)]),
    (10, "bc:24:11:4e:00:10", "proxmox", "Proxmox Server Solutions", "server", 0.3, [(22, "ssh", "OpenSSH", "9.2p1 Debian"), (8006, "https", "Proxmox VE API", None), (111, "rpcbind", None, None)]),
    (11, "bc:24:11:4e:00:11", "homeassistant", "Proxmox Server Solutions", "server", 0.4, [(8123, "http", "Home Assistant", None), (22, "ssh", "OpenSSH", "9.7")]),
    (12, "bc:24:11:4e:00:12", "portainer", "Proxmox Server Solutions", "server", 0.4, [(22, "ssh", "OpenSSH", "9.2p1"), (9443, "https", "Portainer", None), (2283, "http", "Immich", None), (32400, "http", "Plex Media Server", None), (5000, "http", "Frigate", None), (8484, "http", "uvicorn", None)]),
    (13, "00:11:32:aa:bb:13", "nas", "Synology", "nas", 0.5, [(22, "ssh", "OpenSSH", "8.2"), (445, "microsoft-ds", "Samba smbd", "4"), (2049, "nfs", None, None), (5001, "https", "Synology DSM", None)]),
    (20, "d8:bb:c1:22:33:20", "pc-bureau", "Micro-Star INT'L", "desktop", 0.7, [(445, "microsoft-ds", None, None), (3389, "ms-wbt-server", None, None)]),
    (21, "3c:22:fb:12:34:21", "macbook-pro", "Apple", "laptop", 3.5, [(5000, "rtsp", "AirTunes", None)]),
    (30, "5a:1e:22:9b:7c:30", "iphone", None, "phone", 12.0, []),
    (31, "7e:44:10:ab:cd:31", "pixel-8", None, "phone", 15.0, []),
    (40, "98:b8:ba:41:52:40", "nintendo-switch", "Nintendo", "console", 4.0, []),
    (41, "b8:27:eb:ca:fe:41", "octoprint", "Raspberry Pi Foundation", "printer", 1.8, [(22, "ssh", "OpenSSH", "8.4"), (80, "http", "OctoPrint", None)]),
    (50, "ec:71:db:10:11:50", "cam-entree", "Reolink", "camera", 2.2, [(80, "http", None, None), (554, "rtsp", None, None), (9000, "unknown", None, None)]),
    (51, "ec:71:db:10:11:51", "cam-jardin", "Reolink", "camera", 6.5, [(80, "http", None, None), (554, "rtsp", None, None)]),
    (60, "a4:cf:12:de:ad:60", "esp-volet-salon", "Espressif", "iot", 8.0, [(80, "http", "ESPHome", None), (6053, "unknown", None, None)]),
    (61, "a4:cf:12:de:ad:61", "esp-teleinfo", "Espressif", "iot", 9.0, [(80, "http", "ESPHome", None), (6053, "unknown", None, None)]),
    (62, "00:12:4b:00:aa:62", "zigbee2mqtt-slzb", "Texas Instruments", "iot", 1.5, [(80, "http", None, None), (6638, "unknown", None, None)]),
    (70, "f0:ef:86:11:22:70", "chromecast-salon", "Google", "media", 3.0, [(8008, "http", None, None), (8009, "ajp13", None, None)]),
    (71, "cc:f4:11:55:66:71", "tv-samsung", "Samsung Electronics", "media", 2.5, [(8001, "http", None, None), (8002, "https", None, None)]),
    (80, "34:29:8f:77:88:80", "imprimante-hp", "Hewlett Packard", "printer", 5.0, [(80, "http", "HP HTTP Server", None), (631, "ipp", "CUPS", None), (9100, "jetdirect", None, None)]),
    (81, "50:02:91:aa:bb:81", "robot-aspirateur", "Espressif", "iot", 18.0, []),
    (90, "60:01:94:33:44:90", "tondeuse", "Espressif", "iot", 25.0, []),
]


class DemoBackend:
    """Simule un réseau domestique réaliste (latences, appareils intermittents, nouveaux venus)."""

    def __init__(self, cfg: Config, net: NetInfo):
        self.cfg = cfg
        self.net = net
        self.prefix = "192.168.1."
        net.interface, net.ip, net.mac, net.gateway = "eth0", "192.168.1.12", "bc:24:11:4e:00:12", "192.168.1.1"
        import ipaddress

        net.network = ipaddress.ip_network("192.168.1.0/24")
        self.devices = {self.prefix + str(d[0]): d for d in DEMO_DEVICES}
        self.guest_joined = False

    @staticmethod
    def presence(dev, t: float) -> bool:
        """Présence déterministe dans le temps (téléphones absents la journée, etc.)."""
        kind = dev[4]
        hour = time.localtime(t).tm_hour
        if kind == "phone":
            return not (9 <= hour < 17) or (int(t / 1800) % 5 == 0)
        if kind == "laptop":
            return 8 <= hour < 23
        if kind == "console":
            return 18 <= hour < 23
        if dev[2] == "tondeuse":
            return 10 <= hour < 12 or 14 <= hour < 16
        if dev[2] == "robot-aspirateur":
            return int(t / 3600) % 6 != 3
        if dev[2] == "cam-jardin":
            return int(t / 60) % 97 != 0  # coupure Wi-Fi occasionnelle
        return True

    @staticmethod
    def latency(dev, t: float) -> float:
        base = dev[5]
        hour = time.localtime(t).tm_hour
        busy = 1.6 if 19 <= hour < 23 else 1.0
        wave = 1 + 0.25 * math.sin(t / 900 + dev[0])
        spike = 6 if (dev[4] in ("iot", "camera") and random.random() < 0.02) else 1
        return round(max(0.1, base * busy * wave * spike * random.uniform(0.8, 1.3)), 2)

    async def discover(self):
        await asyncio.sleep(0.3)
        t = time.time()
        out = {}
        for ip, d in self.devices.items():
            if self.presence(d, t):
                out[ip] = (d[1], round(d[5] * 0.6, 2))
        # un « invité » apparaît quelques minutes après le démarrage
        if not self.guest_joined and random.random() < 0.15:
            self.guest_joined = True
            self.devices[self.prefix + "142"] = (
                142, "2e:91:c4:05:6b:8e", "galaxy-invite", None, "phone", 20.0, [],
            )
        return out

    async def ping(self, ips):
        await asyncio.sleep(0.2)
        t = time.time()
        out = {}
        for ip in ips:
            d = self.devices.get(ip)
            if d is None:  # cibles externes
                base = {"1.1.1.1": 9.0, "8.8.8.8": 11.0}.get(ip, 15.0)
                hour = time.localtime(t).tm_hour
                lat = base * (1.8 if 20 <= hour < 23 else 1.0) * random.uniform(0.85, 1.4)
                loss = 33.3 if random.random() < 0.01 else 0.0
                out[ip] = {"sent": 3, "recv": 3 if not loss else 2, "loss": loss, "avg": round(lat, 2), "min": round(lat * 0.9, 2), "max": round(lat * 1.2, 2)}
                continue
            if not self.presence(d, t):
                out[ip] = {"sent": 3, "recv": 0, "loss": 100.0, "avg": None, "min": None, "max": None}
                continue
            if d[2] == "tv-samsung":  # ne répond pas au ping (ARP seulement)
                out[ip] = {"sent": 3, "recv": 0, "loss": 100.0, "avg": None, "min": None, "max": None}
                continue
            lat = self.latency(d, t)
            loss = 33.3 if d[4] in ("iot", "phone") and random.random() < 0.05 else 0.0
            out[ip] = {"sent": 3, "recv": 2 if loss else 3, "loss": loss, "avg": lat, "min": round(lat * 0.8, 2), "max": round(lat * 1.4, 2)}
        return out

    async def resolve(self, ip):
        await asyncio.sleep(0.1)
        d = self.devices.get(ip)
        if not d:
            return {}
        if d[4] in ("iot",) and d[2].startswith("esp"):
            return {"mdns": d[2]}
        if d[4] == "desktop":
            return {"netbios": d[2].upper()}
        if d[2] == "robot-aspirateur":
            return {}
        return {"dns": d[2] + ".home"}

    async def deep_scan(self, ip):
        await asyncio.sleep(random.uniform(2, 5))
        d = self.devices.get(ip)
        if not d:
            return None
        os_map = {
            "server": ("Linux 5.15 - 6.8", 98), "nas": ("Linux 4.4 (Synology DSM)", 95),
            "desktop": ("Microsoft Windows 11 22H2", 96), "laptop": ("Apple macOS 14 (Sonoma)", 93),
            "router": ("Linux 5.4 (embedded)", 91), "switch": ("Linux 4.14 (embedded)", 88),
            "camera": ("Linux 3.10 (embedded)", 85), "iot": ("lwIP (ESP32)", 90),
            "printer": ("HP embedded", 92), "media": ("Android TV / Tizen", 80),
            "phone": ("Apple iOS 17" if d[1].startswith("5a") else "Android 14", 86),
        }
        ports = [
            {"port": p, "proto": "tcp", "service": s, "product": pr, "version": v, "extra": None}
            for (p, s, pr, v) in d[6]
        ]
        if d[2] == "portainer" and int(time.time() / 3600) % 4 == 0:
            ports.append({"port": 9090, "proto": "tcp", "service": "http", "product": "Prometheus", "version": None, "extra": None})
        return {"ports": ports, "os": os_map.get(d[4]), "hostname": None, "mac": d[1], "vendor": d[3]}

    # ------------------------------------------------------------ historique
    def backfill(self, db, oui, external_targets: list[str], days_raw: int = 3, days_hourly: int = 30):
        """Génère un historique crédible pour que les graphiques soient parlants dès le départ."""
        from .netutil import is_random_mac

        now = int(time.time())
        now -= now % 60
        dev_ids = {}
        start_raw = now - days_raw * 86400
        start_hourly = now - days_hourly * 86400
        for ip, d in self.devices.items():
            first = start_hourly + random.randint(0, 3) * 86400
            if d[4] in ("phone", "console"):
                first = start_hourly + random.randint(2, 12) * 86400
            did = db.x(
                """INSERT INTO devices(mac, kind, ip, hostname, hostname_source, vendor, random_mac,
                   dev_type, known, watch, online, first_seen, last_seen, last_name_check)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [d[1], "lan", ip, d[2], "dns", d[3] or oui.lookup(d[1]), int(is_random_mac(d[1])),
                 d[4], 1, int(d[4] in ("server", "nas", "router", "camera")), int(self.presence(d, now)), first, now if self.presence(d, now) else now - random.randint(1, 8) * 3600, 0],
            )
            dev_ids[ip] = (did, d, first)
        for t in external_targets:
            did = db.x(
                "INSERT INTO devices(mac, kind, ip, hostname, hostname_source, known, watch, first_seen, last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                [f"ext:{t}", "external", t, t, "config", 1, 1, start_hourly, start_hourly],
            )
            dev_ids[t] = (did, None, start_hourly)

        raw_rows, hourly_rows, net_rows = [], [], []
        for ip, (did, d, first) in dev_ids.items():
            # horaire (plus ancien que la fenêtre brute)
            for h in range(max(first, start_hourly) // 3600 * 3600, start_raw, 3600):
                if d is None:
                    base = {"1.1.1.1": 9.0, "8.8.8.8": 11.0}.get(ip, 15.0)
                    hour = time.localtime(h).tm_hour
                    lat = base * (1.8 if 20 <= hour < 23 else 1.0) * random.uniform(0.9, 1.2)
                    hourly_rows.append((did, h, 60, 1.0, lat, lat * 0.8, lat * 1.9, 0.2))
                    continue
                ups = [self.presence(d, h + m * 60) for m in range(0, 60, 10)]
                up_ratio = sum(ups) / len(ups)
                lat = self.latency(d, h) if up_ratio else None
                hourly_rows.append((did, h, 60, up_ratio, lat, lat and lat * 0.7, lat and lat * 3, 0.5 if up_ratio else None))
            # brut
            for t in range(max(first, start_raw), now, 60):
                if d is None:
                    base = {"1.1.1.1": 9.0, "8.8.8.8": 11.0}.get(ip, 15.0)
                    hour = time.localtime(t).tm_hour
                    lat = base * (1.8 if 20 <= hour < 23 else 1.0) * random.uniform(0.85, 1.4)
                    raw_rows.append((did, t, 1, round(lat, 2), 0.0))
                    continue
                up = self.presence(d, t)
                if not up and d[4] == "phone" and random.random() < 0.8:
                    continue  # pas d'échantillon pour les absences longues
                lat = self.latency(d, t) if up and d[2] != "tv-samsung" else None
                raw_rows.append((did, t, int(up), lat, 0.0 if up else 100.0))
        for t in range(start_raw, now, 60):
            present = [dd for (_, dd, first) in dev_ids.values() if dd and first <= t and self.presence(dd, t)]
            lats = [self.latency(dd, t) for dd in present[:8]]
            net_rows.append((t, len(present), len(self.devices), round(sum(lats) / len(lats), 2) if lats else None))

        db.xmany("INSERT INTO samples(device_id, ts, up, latency, loss) VALUES(?,?,?,?,?)", raw_rows)
        db.xmany(
            "INSERT OR REPLACE INTO samples_hourly(device_id, ts, n, up_ratio, lat_avg, lat_min, lat_max, loss_avg) VALUES(?,?,?,?,?,?,?,?)",
            hourly_rows,
        )
        db.xmany("INSERT OR REPLACE INTO net_samples(ts, online, total, avg_latency) VALUES(?,?,?,?)", net_rows)
        db.set_meta("rollup_until", str(start_raw - start_raw % 3600))
        db.rollup_hourly()
        # quelques événements passés
        pc = dev_ids[self.prefix + "20"][0]
        cam = dev_ids[self.prefix + "51"][0]
        port = dev_ids[self.prefix + "12"][0]
        db.add_event("device_offline", "cam-jardin (192.168.1.51) est hors ligne", cam, "warning", ts=now - 7200)
        db.add_event("device_online", "cam-jardin (192.168.1.51) est de retour en ligne", cam, "info", ts=now - 6900)
        db.add_event("port_opened", "portainer (192.168.1.12) : port 2283/tcp ouvert (Immich)", port, "warning", ts=now - 86400 * 2)
        db.add_event("high_latency", "cam-jardin : latence moyenne 142 ms (seuil 100 ms)", cam, "warning", ts=now - 86400)
        db.add_event("latency_ok", "cam-jardin : latence revenue à la normale (7 ms)", cam, "info", ts=now - 86400 + 1500)
        db.add_event("ip_changed", "PC-BUREAU : IP 192.168.1.35 → 192.168.1.20", pc, "info", ts=now - 86400 * 3)
        log.info("Démo : historique généré (%d échantillons bruts, %d horaires)", len(raw_rows), len(hourly_rows))
