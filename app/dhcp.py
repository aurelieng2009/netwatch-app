"""Sonde DHCP : envoie un DISCOVER en diffusion et collecte les OFFER reçus. Plusieurs
serveurs DHCP qui répondent = un serveur pirate (box mal configurée, routeur ajouté par
erreur, ou attaque). Parsing pur pour être testable sans réseau."""
from __future__ import annotations

import logging
import random
import socket
import struct
import time

log = logging.getLogger("netwatch.dhcp")

MAGIC = b"\x63\x82\x53\x63"
DHCP_DISCOVER, DHCP_OFFER = 1, 2


def build_discover(mac: str, xid: int | None = None) -> bytes:
    """Construit un paquet DHCP DISCOVER (BOOTP + options)."""
    xid = random.getrandbits(32) if xid is None else xid
    chaddr = bytes(int(x, 16) for x in mac.split(":"))[:6].ljust(16, b"\x00")
    pkt = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1, 1, 6, 0, xid, 0, 0x8000,  # op, htype, hlen, hops, xid, secs, flags(broadcast)
        b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,  # ciaddr yiaddr siaddr giaddr
        chaddr, b"\x00" * 64, b"\x00" * 128,
    )
    options = MAGIC + bytes([53, 1, DHCP_DISCOVER])                 # message type = DISCOVER
    options += bytes([55, 4, 1, 3, 6, 51])                          # param request list
    options += bytes([255])                                         # end
    return pkt + options


def parse_offer(data: bytes, xid: int | None = None) -> dict | None:
    """Retourne {server_id, offered_ip} si le paquet est un DHCPOFFER, sinon None."""
    if len(data) < 240 or data[236:240] != MAGIC:
        return None
    op, _htype, _hlen, _hops, rxid = struct.unpack("!BBBBI", data[:8])
    if op != 2:  # BOOTREPLY
        return None
    if xid is not None and rxid != xid:
        return None
    offered_ip = socket.inet_ntoa(data[16:20])  # yiaddr
    # options TLV
    i = 240
    msg_type = None
    server_id = None
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        ln = data[i + 1]
        val = data[i + 2:i + 2 + ln]
        if code == 53 and ln >= 1:
            msg_type = val[0]
        elif code == 54 and ln == 4:
            server_id = socket.inet_ntoa(val)
        i += 2 + ln
    if msg_type != DHCP_OFFER:
        return None
    return {"server_id": server_id, "offered_ip": offered_ip}


def discover_servers(iface: str | None, mac: str, timeout: float = 3.0) -> list[dict] | None:
    """Diffuse un DISCOVER et retourne la liste des serveurs DHCP ayant répondu.
    Retourne None si la sonde n'a pas pu s'exécuter (port 68 occupé, permissions…)."""
    if not mac:
        return None
    xid = random.getrandbits(32)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with_reuseport = getattr(socket, "SO_REUSEPORT", None)
        if with_reuseport:
            try:
                sock.setsockopt(socket.SOL_SOCKET, with_reuseport, 1)
            except OSError:
                pass
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if iface:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
            except OSError:
                pass
        try:
            sock.bind(("", 68))
        except OSError as e:
            log.info("Sonde DHCP indisponible (port 68 occupé ?) : %s", e)
            return None
        sock.sendto(build_discover(mac, xid), ("255.255.255.255", 67))

        servers: dict[str, dict] = {}
        deadline = time.monotonic() + timeout
        sock.settimeout(timeout)
        while time.monotonic() < deadline:
            try:
                sock.settimeout(max(0.1, deadline - time.monotonic()))
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            except OSError:
                break
            offer = parse_offer(data, xid)
            if offer:
                sid = offer["server_id"] or addr[0]
                servers.setdefault(sid, {"server": sid, "offered_ip": offer["offered_ip"], "from": addr[0]})
        return list(servers.values())
    finally:
        sock.close()
