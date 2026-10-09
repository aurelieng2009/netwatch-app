"""Résolution de noms d'hôtes : DNS inverse, mDNS (unicast), NetBIOS."""
from __future__ import annotations

import asyncio
import logging
import random
import re
import socket
import struct

log = logging.getLogger("netwatch.names")


# ---------------------------------------------------------------- DNS utils
def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def decode_name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    """Décode un nom DNS (avec compression). Retourne (nom, offset après le nom)."""
    labels = []
    end = None
    while True:
        if off >= len(buf) or depth > 20:
            raise ValueError("nom DNS invalide")
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", buf[off : off + 2])[0] & 0x3FFF
            if end is None:
                end = off + 2
            name, _ = decode_name(buf, ptr, depth + 1)
            labels.append(name)
            off = end
            return ".".join(x for x in labels if x), end
        labels.append(buf[off + 1 : off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(labels), (end if end is not None else off)


def build_ptr_query(ip: str, qid: int | None = None) -> bytes:
    qid = random.getrandbits(16) if qid is None else qid
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    hdr = struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0)
    return hdr + encode_name(rev) + struct.pack("!HH", 12, 1)


def parse_ptr_response(buf: bytes) -> str | None:
    if len(buf) < 12:
        return None
    _qid, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        _, off = decode_name(buf, off)
        off += 4
    for _ in range(an + ns + ar):
        _, off = decode_name(buf, off)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", buf[off : off + 10])
        off += 10
        if rtype == 12:
            name, _ = decode_name(buf, off)
            return name
        off += rdlen
    return None


# ---------------------------------------------------------------- NetBIOS
def build_nbstat_query(qid: int | None = None) -> bytes:
    qid = random.getrandbits(16) if qid is None else qid
    raw = b"*" + b"\x00" * 15
    enc = b"".join(bytes([0x41 + (c >> 4), 0x41 + (c & 0x0F)]) for c in raw)
    hdr = struct.pack("!HHHHHH", qid, 0x0000, 1, 0, 0, 0)
    return hdr + b"\x20" + enc + b"\x00" + struct.pack("!HH", 0x21, 1)


def parse_nbstat_response(buf: bytes) -> str | None:
    try:
        off = 12
        _, off = decode_name(buf, off)
        rtype, _rclass, _ttl, _rdlen = struct.unpack("!HHIH", buf[off : off + 10])
        if rtype != 0x21:
            return None
        off += 10
        num = buf[off]
        off += 1
        for i in range(num):
            entry = buf[off + i * 18 : off + (i + 1) * 18]
            if len(entry) < 18:
                break
            name = entry[:15].decode("ascii", "replace").strip()
            suffix = entry[15]
            flags = struct.unpack("!H", entry[16:18])[0]
            if suffix == 0x00 and not flags & 0x8000 and name:
                return name
    except (ValueError, IndexError, struct.error):
        return None
    return None


# ---------------------------------------------------------------- transport
class _UDPOnce(asyncio.DatagramProtocol):
    def __init__(self, fut: asyncio.Future):
        self.fut = fut

    def datagram_received(self, data, addr):
        if not self.fut.done():
            self.fut.set_result(data)

    def error_received(self, exc):
        if not self.fut.done():
            self.fut.set_result(None)


async def udp_query(ip: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPOnce(fut), remote_addr=(ip, port)
        )
    except OSError:
        return None
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(fut, timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        transport.close()


# ---------------------------------------------------------------- API
def _is_junk(name: str | None, ip: str) -> bool:
    if not name:
        return True
    n = name.lower()
    if ip in n or ip.replace(".", "-") in n or n.endswith("in-addr.arpa"):
        return True
    return n in ("localhost", "unknown", "*")


def short_name(name: str) -> str:
    return name.rstrip(".").split(".")[0]


async def reverse_dns(ip: str, timeout: float = 2.0) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        host, _, _ = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout
        )
        return None if _is_junk(host, ip) else host.rstrip(".")
    except (OSError, asyncio.TimeoutError):
        return None


async def mdns_name(ip: str, timeout: float = 1.5) -> str | None:
    data = await udp_query(ip, 5353, build_ptr_query(ip), timeout)
    if not data:
        return None
    try:
        name = parse_ptr_response(data)
    except (ValueError, struct.error, IndexError):
        return None
    if name and name.endswith(".local"):
        name = name[: -len(".local")]
    return None if _is_junk(name, ip) else name


async def netbios_name(ip: str, timeout: float = 1.5) -> str | None:
    data = await udp_query(ip, 137, build_nbstat_query(), timeout)
    name = parse_nbstat_response(data) if data else None
    return None if _is_junk(name, ip) else name


async def resolve_all(ip: str) -> dict[str, str]:
    """Interroge toutes les sources en parallèle. Retourne {source: nom}."""
    rdns, mdns, nb = await asyncio.gather(
        reverse_dns(ip), mdns_name(ip), netbios_name(ip), return_exceptions=True
    )
    out = {}
    for src, v in (("dns", rdns), ("mdns", mdns), ("netbios", nb)):
        if isinstance(v, str) and v:
            out[src] = v
    return out


PRIORITY = ("dns", "mdns", "netbios", "nmap")


def best_name(names: dict[str, str]) -> tuple[str | None, str | None]:
    for src in PRIORITY:
        if names.get(src):
            return short_name(names[src]), src
    return None, None


_SAFE = re.compile(r"[^\w.\- ]", re.UNICODE)


def clean(name: str) -> str:
    return _SAFE.sub("", name)[:80]
