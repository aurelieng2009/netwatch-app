"""Scan ARP en Python pur (socket AF_PACKET, nécessite CAP_NET_RAW)."""
from __future__ import annotations

import logging
import select
import socket
import struct
import time

from .netutil import format_mac, normalize_mac

log = logging.getLogger("netwatch.arp")

ETH_P_ARP = 0x0806
BROADCAST = b"\xff" * 6


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in normalize_mac(mac).split(":"))


def build_request(src_mac: bytes, src_ip: str, dst_ip: str) -> bytes:
    eth = BROADCAST + src_mac + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, 1,
        src_mac, socket.inet_aton(src_ip),
        b"\x00" * 6, socket.inet_aton(dst_ip),
    )
    return eth + arp


def parse_reply(frame: bytes) -> tuple[str, str] | None:
    """Retourne (ip, mac) si la trame est une réponse ARP IPv4, sinon None."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x06":
        return None
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", frame[14:22])
    if ptype != 0x0800 or hlen != 6 or plen != 4 or op != 2:
        return None
    sha = frame[22:28]
    spa = socket.inet_ntoa(frame[28:32])
    return spa, format_mac(sha)


def arp_scan(
    iface: str,
    src_mac: str,
    src_ip: str,
    targets: list[str],
    timeout: float = 2.0,
    retries: int = 2,
    inter: float = 0.002,
    seen: dict[str, set[str]] | None = None,
) -> dict[str, tuple[str, float]]:
    """Envoie une requête ARP à chaque cible. Retourne {ip: (mac, rtt_ms)} (première réponse).
    Si `seen` est fourni, il reçoit toutes les MAC ayant répondu pour chaque IP : plusieurs
    MAC pour une même IP = conflit d'adresse (ou usurpation ARP)."""
    results: dict[str, tuple[str, float]] = {}
    target_set = set(targets)
    smac = _mac_bytes(src_mac)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.bind((iface, ETH_P_ARP))
        sent_at: dict[str, float] = {}

        def drain(until: float) -> None:
            while True:
                remaining = until - time.monotonic()
                if remaining <= 0:
                    return
                r, _, _ = select.select([sock], [], [], remaining)
                if not r:
                    return
                frame = sock.recv(2048)
                now = time.monotonic()
                parsed = parse_reply(frame)
                if not parsed:
                    continue
                ip, mac = parsed
                if seen is not None and ip in target_set:
                    seen.setdefault(ip, set()).add(mac)
                if ip in target_set and ip not in results:
                    rtt = (now - sent_at.get(ip, now)) * 1000
                    results[ip] = (mac, round(rtt, 2))

        for _ in range(max(1, retries)):
            pending = [ip for ip in targets if ip not in results]
            if not pending:
                break
            for ip in pending:
                sent_at[ip] = time.monotonic()
                try:
                    sock.send(build_request(smac, src_ip, ip))
                except OSError as e:
                    log.debug("envoi ARP %s: %s", ip, e)
                # lit les réponses au fil de l'eau pour garder des RTT réalistes
                drain(time.monotonic() + inter)
            drain(time.monotonic() + timeout)
    finally:
        sock.close()
    return results


def read_arp_cache(iface: str | None = None) -> dict[str, str]:
    """Entrées complètes du cache ARP du noyau (/proc/net/arp) : {ip: mac}."""
    out: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) < 6:
                    continue
                ip, flags, mac, dev = p[0], p[2], p[3], p[5]
                if int(flags, 16) & 0x2 and mac != "00:00:00:00:00:00":
                    if iface is None or dev == iface:
                        out[ip] = mac.lower()
    except OSError:
        pass
    return out
