"""Sondes actives du diagnostic de latence : connexion TCP, DNS chronométré, bufferbloat,
santé du scanner lui-même. (Ping, traceroute et MTU sont dans icmp.py.)"""
from __future__ import annotations

import asyncio
import os
import random
import socket
import struct
import threading
import time
import urllib.request

from . import icmp
from .names import encode_name


# ------------------------------------------------------------------ TCP
async def tcp_connect(host: str, port: int, count: int = 3, timeout: float = 2.0) -> dict:
    """Temps d'établissement TCP (SYN → SYN/ACK). Comparé au ping, il révèle les équipements
    qui dépriorisent l'ICMP : ping lent mais TCP rapide = fausse alerte."""
    rtts, errors = [], []
    for _ in range(count):
        t0 = time.monotonic()
        try:
            _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            rtts.append((time.monotonic() - t0) * 1000)
            w.close()
            try:
                await w.wait_closed()
            except OSError:
                pass
        except (OSError, asyncio.TimeoutError) as e:
            errors.append(type(e).__name__)
        await asyncio.sleep(0.1)
    st = icmp.stats_from_rtts(rtts, count)
    st.update(host=host, port=port, median=icmp.percentile(rtts, 50), errors=errors[:3])
    return st


# ------------------------------------------------------------------ DNS
def build_a_query(name: str, qid: int) -> bytes:
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    return hdr + encode_name(name) + struct.pack("!HH", 1, 1)


def parse_dns_header(buf: bytes) -> tuple[int, int, int] | None:
    """(id, rcode, nb réponses)."""
    if len(buf) < 12:
        return None
    qid, flags, _qd, an = struct.unpack("!HHHH", buf[:8])
    if not flags & 0x8000:
        return None
    return qid, flags & 0x000F, an


class _DNSProto(asyncio.DatagramProtocol):
    def __init__(self, fut: asyncio.Future, qid: int):
        self.fut, self.qid = fut, qid

    def datagram_received(self, data, addr):
        h = parse_dns_header(data)
        if h and h[0] == self.qid and not self.fut.done():
            self.fut.set_result((time.monotonic(), h[1], h[2]))

    def error_received(self, exc):
        if not self.fut.done():
            self.fut.set_exception(exc)


async def dns_time(server: str, name: str, timeout: float = 2.0) -> dict:
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    qid = random.getrandbits(16)
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: _DNSProto(fut, qid), remote_addr=(server, 53))
    except OSError as e:
        return {"ok": False, "ms": None, "rcode": None, "error": str(e)[:80]}
    try:
        t0 = time.monotonic()
        transport.sendto(build_a_query(name, qid))
        t1, rcode, answers = await asyncio.wait_for(fut, timeout)
        return {"ok": rcode in (0, 3), "ms": round((t1 - t0) * 1000, 2), "rcode": rcode, "answers": answers}
    except (asyncio.TimeoutError, OSError) as e:
        return {"ok": False, "ms": None, "rcode": None, "error": "délai dépassé" if isinstance(e, asyncio.TimeoutError) else str(e)[:80]}
    finally:
        transport.close()


async def dns_probe(server: str, domain: str) -> dict:
    """Requête en cache (domaine connu, 3 essais, médiane des 2 derniers) et hors cache
    (sous-domaine aléatoire → NXDOMAIN, oblige le résolveur à interroger Internet)."""
    cached = [await dns_time(server, domain) for _ in range(3)]
    uncached = await dns_time(server, f"nw-{random.getrandbits(40):x}.{domain}")
    ok_times = [c["ms"] for c in cached[1:] if c["ok"] and c["ms"] is not None]
    return {
        "server": server,
        "ok": any(c["ok"] for c in cached),
        "cached_ms": icmp.percentile(ok_times, 50),
        "first_ms": cached[0]["ms"],
        "uncached_ms": uncached["ms"] if uncached["ok"] else None,
        "failures": sum(1 for c in cached if not c["ok"]) + (0 if uncached["ok"] else 1),
    }


def system_resolvers() -> list[str]:
    out = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and p[0] == "nameserver" and ":" not in p[1] and not p[1].startswith("127."):
                    out.append(p[1])
    except OSError:
        pass
    return out


# ------------------------------------------------------------------ bufferbloat
def bufferbloat(url: str, target: str, seconds: float = 8.0, idle_seconds: float = 3.0) -> dict:
    """Latence au repos puis pendant un téléchargement saturant. Une forte hausse sous charge
    (bufferbloat) est la cause n° 1 des « lags » en visio / jeu quand quelqu'un télécharge."""
    samples: list[tuple[float, float | None, str]] = []
    phase = {"v": "idle"}
    stop = threading.Event()

    def pinger():
        while not stop.is_set():
            r = icmp.multiping([target], 1, 0.0, 0.8)[target]
            samples.append((time.monotonic(), r["avg"], phase["v"]))
            stop.wait(0.2)

    th = threading.Thread(target=pinger, daemon=True)
    th.start()
    time.sleep(idle_seconds)
    phase["v"] = "load"
    got, t0, err = 0, time.monotonic(), None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetWatch"})
        with urllib.request.urlopen(req, timeout=10) as r:
            while time.monotonic() - t0 < seconds:
                chunk = r.read(65536)
                if not chunk:
                    break
                got += len(chunk)
    except OSError as e:
        err = str(e)[:120]
    dur = max(0.001, time.monotonic() - t0)
    stop.set()
    th.join(2)
    idle = [s[1] for s in samples if s[2] == "idle" and s[1] is not None]
    load = [s[1] for s in samples if s[2] == "load" and s[1] is not None]
    lost = sum(1 for s in samples if s[2] == "load" and s[1] is None)
    idle_med = icmp.percentile(idle, 50)
    load_p95 = icmp.percentile(load, 95)
    increase = round(load_p95 - idle_med, 1) if idle_med is not None and load_p95 is not None else None
    return {
        "target": target, "idle_median": idle_med, "load_median": icmp.percentile(load, 50), "load_p95": load_p95,
        "increase": increase, "grade": bloat_grade(increase), "loaded_loss": lost,
        "mbps": round(got * 8 / dur / 1e6, 1), "bytes": got, "error": err,
    }


def bloat_grade(increase: float | None) -> str | None:
    """Barème proche de celui de Waveform : A < 30 ms, B < 60, C < 200, D < 400, F au-delà."""
    if increase is None:
        return None
    for limit, g in ((5, "A+"), (30, "A"), (60, "B"), (200, "C"), (400, "D")):
        if increase < limit:
            return g
    return "F"


# ------------------------------------------------------------------ santé du scanner
def read_netdev(iface: str) -> dict:
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                name, _, rest = line.partition(":")
                if name.strip() == iface:
                    v = [int(x) for x in rest.split()[:16]]
                    return {"rx_errs": v[2], "rx_drop": v[3], "tx_errs": v[10], "tx_drop": v[11]}
    except (OSError, ValueError, IndexError):
        pass
    return {}


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def self_health(iface: str | None) -> dict:
    load = (_read("/proc/loadavg") or "").split()[:3]
    out: dict = {
        "load": [float(x) for x in load] if len(load) == 3 else None,
        "cores": os.cpu_count(),
        "iface": iface,
    }
    if iface:
        speed = _read(f"/sys/class/net/{iface}/speed")
        out.update({
            "speed": int(speed) if speed and speed.lstrip("-").isdigit() and int(speed) > 0 else None,
            "duplex": _read(f"/sys/class/net/{iface}/duplex"),
            "wireless": os.path.isdir(f"/sys/class/net/{iface}/wireless"),
            "counters": read_netdev(iface),
        })
    psi = _read("/proc/pressure/cpu")
    if psi:
        try:
            out["cpu_pressure_avg60"] = float(psi.split()[2].split("=")[1])
        except (IndexError, ValueError):
            pass
    return out


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return host
