"""Scan approfondi via nmap (sortie XML parsée)."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import shlex
import shutil
import xml.etree.ElementTree as ET

log = logging.getLogger("netwatch.nmap")


DEFAULT_ARGS = "-sS -sV --version-light -O --osscan-limit --top-ports 1000 -T4 --host-timeout 300s"

# Seules ces options sont acceptées. Tout le reste est refusé : scripts NSE (--script), lecture ou
# écriture de fichiers (-iL, -oN…), cibles supplémentaires, usurpation (-S, -D), -T5, débit non borné.
_FLAGS = {"-sS", "-sT", "-sV", "-sU", "-O", "-Pn", "-n", "-F", "-r", "--open", "--version-light", "--version-all",
          "--osscan-limit", "--osscan-guess", "-T0", "-T1", "-T2", "-T3", "-T4"}
_TIME = re.compile(r"^\d{1,6}(ms|s|m|h)?$")
_VALUED = {
    "--top-ports": lambda v: v.isdigit() and 1 <= int(v) <= 65535,
    "-p": lambda v: re.fullmatch(r"[0-9TU:,\-]{1,200}", v) is not None,
    "--host-timeout": lambda v: _TIME.match(v) is not None,
    "--max-retries": lambda v: v.isdigit() and int(v) <= 10,
    "--version-intensity": lambda v: v.isdigit() and int(v) <= 9,
    "--max-rate": lambda v: v.isdigit() and 1 <= int(v) <= 5000,
    "--scan-delay": lambda v: _TIME.match(v) is not None,
    "--max-scan-delay": lambda v: _TIME.match(v) is not None,
    "--max-rtt-timeout": lambda v: _TIME.match(v) is not None,
    "--initial-rtt-timeout": lambda v: _TIME.match(v) is not None,
}


def safe_args(args: str) -> list[str]:
    """Découpe et contrôle les arguments nmap. Lève ValueError à la première option non autorisée."""
    try:
        tokens = shlex.split(args or "")
    except ValueError as e:
        raise ValueError(f"arguments nmap illisibles ({e})") from e
    if len(tokens) > 30:
        raise ValueError("trop d'arguments nmap")
    out, i = [], 0
    while i < len(tokens):
        t = tokens[i]
        if t in _FLAGS:
            out.append(t)
        else:
            opt, eq, val = t.partition("=")
            if t.startswith("-p") and not t.startswith("--") and len(t) > 2:
                opt, val, eq = "-p", t[2:], "="
            if opt not in _VALUED:
                raise ValueError(f"option nmap non autorisée : {t}")
            if not eq:
                i += 1
                if i >= len(tokens):
                    raise ValueError(f"valeur manquante pour {opt}")
                val = tokens[i]
            if not _VALUED[opt](val):
                raise ValueError(f"valeur refusée pour {opt} : {val}")
            out += [opt, val]
        i += 1
    return out


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def parse_nmap_xml(xml: str) -> dict[str, dict]:
    """Retourne {ip: {ports: [...], os: (nom, précision) | None, hostname, mac, vendor}}."""
    out: dict[str, dict] = {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        log.warning("XML nmap invalide: %s", e)
        return out
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = mac = vendor = None
        for a in host.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac = (a.get("addr") or "").lower() or None
                vendor = a.get("vendor")
        if not ip:
            continue
        hostname = None
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")
        ports = []
        for p in host.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append(
                {
                    "port": int(p.get("portid")),
                    "proto": p.get("protocol", "tcp"),
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                    "extra": svc.get("extrainfo") if svc is not None else None,
                }
            )
        os_guess = None
        best = None
        for m in host.findall("os/osmatch"):
            acc = int(m.get("accuracy", "0"))
            if best is None or acc > best[1]:
                best = (m.get("name"), acc)
        if best:
            os_guess = best
        out[ip] = {
            "ports": ports,
            "os": os_guess,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
        }
    return out


async def scan_host(ip: str, args: str, timeout: float = 900) -> dict | None:
    """Lance nmap sur un hôte. Retourne le résultat parsé, ou None en cas d'échec."""
    try:
        ipaddress.ip_address(ip)
        opts = safe_args(args)
    except ValueError as e:
        log.error("Scan nmap de %s annulé : %s", ip, e)
        return None
    cmd = ["nmap", *opts, "-oX", "-", ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError:
        log.error("nmap introuvable")
        return None
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        log.warning("nmap %s : délai dépassé", ip)
        return None
    if proc.returncode != 0:
        log.warning("nmap %s a échoué (%s): %s", ip, proc.returncode, stderr.decode()[:300])
        return None
    parsed = parse_nmap_xml(stdout.decode("utf-8", "replace"))
    # hôte « down » pour nmap (pare-feu) : on renvoie un résultat vide mais valide
    return parsed.get(ip, {"ports": [], "os": None, "hostname": None, "mac": None, "vendor": None, "down": True})
