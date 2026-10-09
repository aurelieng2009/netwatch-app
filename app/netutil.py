"""Utilitaires réseau : interface, sous-réseau, passerelle, base OUI."""
from __future__ import annotations

import fcntl
import ipaddress
import logging
import os
import socket
import struct

log = logging.getLogger("netwatch.net")

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B
SIOCGIFHWADDR = 0x8927


def default_route() -> tuple[str | None, str | None]:
    """Retourne (interface, passerelle) de la route par défaut via /proc/net/route."""
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                iface, dest, gw = parts[0], parts[1], parts[2]
                if dest == "00000000":
                    gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw, 16)))
                    return iface, gw_ip
    except OSError:
        pass
    return None, None


def _ioctl(iface: str, req: int) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return fcntl.ioctl(s.fileno(), req, struct.pack("256s", iface[:15].encode()))
    finally:
        s.close()


def iface_ipv4(iface: str) -> tuple[str, str] | None:
    """(ip, netmask) de l'interface."""
    try:
        ip = socket.inet_ntoa(_ioctl(iface, SIOCGIFADDR)[20:24])
        mask = socket.inet_ntoa(_ioctl(iface, SIOCGIFNETMASK)[20:24])
        return ip, mask
    except OSError:
        return None


def iface_mac(iface: str) -> str | None:
    try:
        return format_mac(_ioctl(iface, SIOCGIFHWADDR)[18:24])
    except OSError:
        try:
            with open(f"/sys/class/net/{iface}/address") as f:
                return f.read().strip().lower()
        except OSError:
            return None


def format_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def normalize_mac(mac: str) -> str:
    h = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    return ":".join(h[i : i + 2] for i in range(0, 12, 2))


def parse_nets(patterns: list[str] | None) -> list[ipaddress.IPv4Network]:
    """Compile une liste d'IP ou de CIDR en réseaux IPv4. Les entrées invalides sont ignorées
    (avec un avertissement) pour qu'une faute de frappe ne fasse pas planter le démarrage."""
    out: list[ipaddress.IPv4Network] = []
    for p in patterns or []:
        p = p.strip()
        if not p:
            continue
        try:
            out.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            log.warning("Motif d'exclusion ignoré (ni IP ni CIDR valide) : %r", p)
    return out


def ip_in_nets(ip: str | None, nets: list[ipaddress.IPv4Network]) -> bool:
    if not ip or not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def is_random_mac(mac: str) -> bool:
    """Bit 'locally administered' positionné => MAC privée/aléatoire (téléphones…)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


class NetInfo:
    def __init__(self, interface: str | None = None, subnet: str | None = None,
                 exclude: list[str] | None = None):
        self.exclude_nets = parse_nets(exclude)
        self.extra_excluded: set[str] = set()  # IP exclues par appareil (mises à jour par le moteur)
        iface, gw = default_route()
        self.interface = interface or iface or "eth0"
        self.gateway = gw if (interface is None or interface == iface) else None
        addr = iface_ipv4(self.interface)
        self.ip = addr[0] if addr else None
        self.mac = iface_mac(self.interface)
        if subnet:
            self.network = ipaddress.ip_network(subnet, strict=False)
        elif addr:
            self.network = ipaddress.ip_network(f"{addr[0]}/{addr[1]}", strict=False)
        else:
            self.network = None
        if self.network and self.network.num_addresses > 4096:
            log.warning(
                "Sous-réseau %s très grand (%d adresses) : restreint à /22 autour de l'IP locale",
                self.network, self.network.num_addresses,
            )
            base = self.ip or str(self.network.network_address)
            self.network = ipaddress.ip_network(f"{base}/22", strict=False)

    def is_excluded(self, ip: str | None) -> bool:
        return bool(ip) and (ip in self.extra_excluded or ip_in_nets(ip, self.exclude_nets))

    def hosts(self) -> list[str]:
        if not self.network:
            return []
        return [str(h) for h in self.network.hosts() if not self.is_excluded(str(h))]

    def as_dict(self) -> dict:
        return {
            "interface": self.interface,
            "ip": self.ip,
            "mac": self.mac,
            "gateway": self.gateway,
            "subnet": str(self.network) if self.network else None,
            "excluded": [str(n) for n in self.exclude_nets],
        }


class OUIDB:
    """Base constructeur à partir du fichier nmap-mac-prefixes (fourni par le paquet nmap)."""

    PATHS = (
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/local/share/nmap/nmap-mac-prefixes",
        os.path.join(os.path.dirname(__file__), "nmap-mac-prefixes"),
    )

    def __init__(self):
        self.db: dict[str, str] = {}
        for p in self.PATHS:
            if os.path.exists(p):
                self._load(p)
                break
        if not self.db:
            log.warning("Base OUI introuvable : pas de résolution constructeur")

    def _load(self, path: str) -> None:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                prefix, _, name = line.partition(" ")
                self.db[prefix.upper()] = name.strip()
        log.info("Base OUI chargée : %d préfixes (%s)", len(self.db), path)

    def lookup(self, mac: str) -> str | None:
        h = "".join(c for c in mac.upper() if c in "0123456789ABCDEF")
        # nmap-mac-prefixes contient des préfixes de 6, 7 et 9 hex (MA-L / MA-M / MA-S)
        for n in (9, 7, 6):
            v = self.db.get(h[:n])
            if v:
                return v
        return None
