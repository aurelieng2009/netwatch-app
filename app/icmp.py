"""ICMP en Python pur : ping multi-cibles, traceroute et sondage du MTU de chemin.
Socket RAW (CAP_NET_RAW) avec repli sur socket DGRAM non privilégiée pour le ping
(net.ipv4.ping_group_range). Traceroute et MTU exigent la socket RAW."""
from __future__ import annotations

import errno
import logging
import math
import os
import random
import select
import socket
import struct
import time

log = logging.getLogger("netwatch.icmp")

ICMP_ECHO = 8
ICMP_ECHO_REPLY = 0
ICMP_UNREACH = 3
ICMP_TIME_EXCEEDED = 11
MAGIC = b"NWATCH"
BASE_PAYLOAD = 32  # MAGIC (6) + token (4) + bourrage (22), comme en V1

# Linux : IP_MTU_DISCOVER / IP_PMTUDISC_PROBE (DF positionné, pas de fragmentation locale)
IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_PROBE = getattr(socket, "IP_PMTUDISC_PROBE", 3)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_echo(ident: int, seq: int, token: int, size: int = BASE_PAYLOAD) -> bytes:
    """Echo-request ; `size` = taille de la charge utile ICMP (≥ 10 octets)."""
    payload = MAGIC + struct.pack("!I", token)
    payload += b"\x00" * max(0, size - len(payload))
    hdr = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, ident, seq)
    csum = checksum(hdr + payload)
    return struct.pack("!BBHHH", ICMP_ECHO, 0, csum, ident, seq) + payload


def _open_socket() -> tuple[socket.socket, bool]:
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP), True
    except PermissionError:
        return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP), False


def parse_reply(packet: bytes, raw: bool) -> tuple[int, int, int] | None:
    """Retourne (ident, seq, token) d'un echo-reply NetWatch, sinon None."""
    if raw:
        if len(packet) < 20:
            return None
        ihl = (packet[0] & 0x0F) * 4
        packet = packet[ihl:]
    if len(packet) < 18:
        return None
    typ, _code, _csum, ident, seq = struct.unpack("!BBHHH", packet[:8])
    if typ != ICMP_ECHO_REPLY or packet[8:14] != MAGIC:
        return None
    (token,) = struct.unpack("!I", packet[14:18])
    return ident, seq, token


def parse_error(packet: bytes) -> tuple[int, int, int, int] | None:
    """Message d'erreur ICMP (time-exceeded, unreachable) reçu sur socket RAW, qui cite
    notre echo-request. Retourne (type, code, ident, seq) de la requête d'origine."""
    if len(packet) < 20:
        return None
    ihl = (packet[0] & 0x0F) * 4
    icmp = packet[ihl:]
    if len(icmp) < 8 + 20 + 8:
        return None
    typ, code = icmp[0], icmp[1]
    if typ not in (ICMP_TIME_EXCEEDED, ICMP_UNREACH):
        return None
    inner = icmp[8:]
    inner_ihl = (inner[0] & 0x0F) * 4
    if inner[9] != socket.IPPROTO_ICMP or len(inner) < inner_ihl + 8:
        return None
    otyp, _ocode, _ocsum, ident, seq = struct.unpack("!BBHHH", inner[inner_ihl:inner_ihl + 8])
    if otyp != ICMP_ECHO:
        return None
    return typ, code, ident, seq


def stats_from_rtts(rtts: list[float], sent: int) -> dict:
    """Statistiques d'une série de RTT. La gigue est l'écart moyen entre mesures successives
    (RFC 3550, sans lissage) : plus parlante que l'écart-type pour la voix et le jeu."""
    sent = sent or 1
    out = {
        "sent": sent,
        "recv": len(rtts),
        "loss": round(100.0 * (sent - len(rtts)) / sent, 1),
        "avg": round(sum(rtts) / len(rtts), 2) if rtts else None,
        "min": round(min(rtts), 2) if rtts else None,
        "max": round(max(rtts), 2) if rtts else None,
        "jitter": None,
        "stdev": None,
    }
    if len(rtts) >= 2:
        diffs = [abs(b - a) for a, b in zip(rtts, rtts[1:])]
        out["jitter"] = round(sum(diffs) / len(diffs), 2)
        mean = sum(rtts) / len(rtts)
        out["stdev"] = round(math.sqrt(sum((r - mean) ** 2 for r in rtts) / (len(rtts) - 1)), 2)
    return out


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    k = (len(v) - 1) * p / 100
    lo, hi = math.floor(k), math.ceil(k)
    return round(v[lo] + (v[hi] - v[lo]) * (k - lo), 2)


def multiping(
    hosts: list[str], count: int = 3, interval: float = 0.25, timeout: float = 1.0,
    size: int = BASE_PAYLOAD, keep_rtts: bool = False,
) -> dict[str, dict]:
    """Ping chaque hôte `count` fois. Retourne {ip: {sent, recv, loss, avg, min, max, jitter, stdev}}."""
    stats = {h: {"sent": 0, "rtts": []} for h in hosts}
    if not hosts:
        return {}
    sock, raw = _open_socket()
    ident = os.getpid() & 0xFFFF
    token = random.getrandbits(32)
    pending: dict[int, tuple[str, float]] = {}  # seq -> (ip, t_envoi)
    seq = random.randrange(0, 0xFFFF)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)

        def drain(until: float) -> None:
            while True:
                remaining = until - time.monotonic()
                if remaining <= 0:
                    return
                r, _, _ = select.select([sock], [], [], remaining)
                if not r:
                    return
                data, addr = sock.recvfrom(4096)
                now = time.monotonic()
                parsed = parse_reply(data, raw)
                if not parsed:
                    continue
                rid, rseq, rtok = parsed
                if rtok != token or (raw and rid != ident):
                    continue
                entry = pending.pop(rseq, None)
                if entry and entry[0] == addr[0]:
                    stats[entry[0]]["rtts"].append((now - entry[1]) * 1000)

        for _round in range(count):
            for h in hosts:
                seq = (seq + 1) & 0xFFFF
                pkt = build_echo(ident, seq, token, size)
                pending[seq] = (h, time.monotonic())
                try:
                    sock.sendto(pkt, (h, 0))
                    stats[h]["sent"] += 1
                except OSError as e:
                    log.debug("ping %s: %s", h, e)
                    pending.pop(seq, None)
                drain(time.monotonic() + 0.001)
            drain(time.monotonic() + interval)
        drain(time.monotonic() + timeout)
    finally:
        sock.close()

    out = {}
    for h, s in stats.items():
        out[h] = stats_from_rtts(s["rtts"], s["sent"] or count)
        if keep_rtts:
            out[h]["rtts"] = [round(r, 3) for r in s["rtts"]]
    return out


def traceroute(dest: str, max_hops: int = 20, probes: int = 3, timeout: float = 2.0) -> list[dict]:
    """Traceroute ICMP : toutes les sondes partent d'un coup (quelques secondes au total).
    Retourne [{ttl, ip, rtts, loss, avg}] jusqu'à la destination. Exige CAP_NET_RAW."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    ident = random.getrandbits(16)
    token = random.getrandbits(32)
    seq0 = random.randrange(0, 0xFFFF - max_hops * probes - 1)
    sent: dict[int, tuple[int, float]] = {}  # seq -> (ttl, t_envoi)
    hops: dict[int, dict] = {ttl: {"ttl": ttl, "ip": None, "rtts": []} for ttl in range(1, max_hops + 1)}
    reached: int | None = None
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        for p in range(probes):
            for ttl in range(1, max_hops + 1):
                seq = seq0 + p * max_hops + ttl
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                sent[seq] = (ttl, time.monotonic())
                try:
                    sock.sendto(build_echo(ident, seq, token), (dest, 0))
                except OSError as e:
                    log.debug("traceroute %s ttl %d: %s", dest, ttl, e)
            time.sleep(0.05)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r, _, _ = select.select([sock], [], [], deadline - time.monotonic())
            if not r:
                break
            data, addr = sock.recvfrom(4096)
            now = time.monotonic()
            rseq = None
            rep = parse_reply(data, raw=True)
            if rep and rep[0] == ident and rep[2] == token:
                rseq = rep[1]
            else:
                err = parse_error(data)
                if err and err[2] == ident:
                    rseq = err[3]
            if rseq is None or rseq not in sent:
                continue
            ttl, t0 = sent.pop(rseq)
            hop = hops[ttl]
            hop["ip"] = hop["ip"] or addr[0]
            hop["rtts"].append(round((now - t0) * 1000, 2))
            if addr[0] == dest:
                reached = ttl if reached is None else min(reached, ttl)
    finally:
        sock.close()
    last = reached or max((t for t, h in hops.items() if h["ip"]), default=0)
    out = []
    for ttl in range(1, last + 1):
        h = hops[ttl]
        h["loss"] = round(100.0 * (probes - len(h["rtts"])) / probes, 1)
        h["avg"] = round(sum(h["rtts"]) / len(h["rtts"]), 2) if h["rtts"] else None
        out.append(h)
    return out


def _probe_size(sock: socket.socket, dest: str, size: int, ident: int, token: int, timeout: float) -> bool | None:
    """Un echo DF de `size` octets de charge utile passe-t-il ? None = trop gros pour l'interface locale."""
    for attempt in range(2):
        seq = random.getrandbits(16)
        try:
            sock.sendto(build_echo(ident, seq, token, size), (dest, 0))
        except OSError as e:
            if e.errno == errno.EMSGSIZE:
                return None
            raise
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r, _, _ = select.select([sock], [], [], deadline - time.monotonic())
            if not r:
                break
            data, addr = sock.recvfrom(4096)
            rep = parse_reply(data, raw=True)
            if rep and rep[0] == ident and rep[1] == seq and addr[0] == dest:
                return True
            err = parse_error(data)
            if err and err[2] == ident and err[3] == seq and err[0] == ICMP_UNREACH and err[1] == 4:
                return False  # « fragmentation nécessaire » : un routeur a un MTU plus petit
    return False


def path_mtu(dest: str, timeout: float = 1.0, lo: int = 548, hi: int = 1472) -> dict:
    """Recherche dichotomique du plus gros echo DF qui passe. Retourne {mtu, payload, ok}.
    mtu = charge utile + 28 (en-têtes IP + ICMP). 1500 = Ethernet normal, 1492 = PPPoE."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    ident, token = random.getrandbits(16), random.getrandbits(32)
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE)
        if not _probe_size(sock, dest, lo, ident, token, timeout):
            return {"mtu": None, "payload": None, "ok": False}
        best = lo
        a, b = lo + 1, hi
        while a <= b:
            mid = (a + b) // 2
            if _probe_size(sock, dest, mid, ident, token, timeout):
                best, a = mid, mid + 1
            else:
                b = mid - 1
        return {"mtu": best + 28, "payload": best, "ok": True}
    finally:
        sock.close()
