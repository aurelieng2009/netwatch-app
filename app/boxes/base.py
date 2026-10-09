"""Socle commun des fournisseurs de box (Bouygues, Free, Orange, SFR).

Chaque fournisseur sait détecter sa box, s'y connecter et renvoyer un relevé **normalisé** :

    {"device":   {"model", "uptime", "boots", "firmware", "ftth"},
     "summary":  {"internet_up": bool | None, "wifi_radio": bool | None, "wifi_guest": bool | None},
     "wan":      {"ip", "ip6", "gateway", "dns", "state"},
     "stats":    {"rx_bytes", "tx_bytes", "rx_kbps", "tx_kbps", "rx_occ", "tx_occ",
                  "rx_contract_kbps", "tx_contract_kbps"} | None,
     "hosts":    [{"mac", "ip", "hostname", "active", "link", "wifi", "rssi", "port", "wex", "rate",
                   "type", "lastseen", "ap", "ap_kind", ["ssid"]}] | None,
     "repeaters": [...] | None, "radios": {...} | None,
     "auth_error": str | None, "endpoints": {chemin: erreur}}

Le champ `link` suit la convention de la Bbox (« Ethernet », « Wifi 2.4 », « Wifi 5 », « Wifi 6 »,
« Wifi MLO ») : le suivi Wi-Fi en déduit la bande. Les données que la box ne fournit pas restent à None.

Sécurité : les box présentent souvent un certificat auto-signé (ou parlent en HTTP clair sur le LAN),
si bien que le mot de passe ne part que vers une adresse privée ou un nom de box connu.
"""
from __future__ import annotations

import http.cookiejar
import ipaddress
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from ..netutil import normalize_mac

KNOWN_NAME_SUFFIXES = (".bytel.fr", ".freebox.fr", ".home", ".lan", ".local")


class BoxError(Exception):
    """Erreur lisible côté interface."""


class BoxAuthError(BoxError):
    """Identifiants refusés par la box."""


class BoxApprovalRequired(BoxError):
    """La box attend qu'on autorise NetWatch (Freebox : bouton sur la façade)."""


def host_allowed(host: str) -> bool:
    """Les identifiants ne partent que vers le LAN ou un nom de box connu."""
    host = (host or "").strip().lower()
    if not host or any(c in host for c in "/@ :\\"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_link_local
    except ValueError:
        pass
    if "." not in host:                      # « livebox », « mabbox » : nom résolu localement
        return True
    return host.endswith(KNOWN_NAME_SUFFIXES)


def mac_or_none(raw) -> str | None:
    raw = str(raw or "")
    return normalize_mac(raw) if len([c for c in raw if c.isalnum()]) == 12 else None


def to_int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return default


def empty_snapshot() -> dict:
    return {"device": {"model": None, "uptime": None, "boots": None, "firmware": None, "ftth": False},
            "summary": {"internet_up": None, "wifi_radio": None, "wifi_guest": None},
            "wan": {"ip": None, "ip6": None, "gateway": None, "dns": None, "state": None},
            "stats": None, "hosts": None, "repeaters": None, "radios": None,
            "auth_error": None, "endpoints": {}}


def assign_access_points(hosts: list[dict], repeaters: list[dict], box_label: str = "Box") -> None:
    """Ajoute à chaque appareil `ap` (nom de la box ou d'un répéteur) et `ap_kind`.

    Pour le Wi-Fi, la liste des stations de chaque répéteur fait foi ; à défaut, l'index `wex`
    déclaré par la box. Les appareils filaires et les répéteurs eux-mêmes sont rattachés à la box."""
    by_station = {mac: r for r in repeaters for mac in r["stations"]}
    by_index = {r["index"]: r for r in repeaters if r["index"] is not None}
    rep_macs = {r["mac"] for r in repeaters}
    for h in hosts:
        rep = None
        if h["wifi"] and h["mac"] not in rep_macs:
            rep = by_station.get(h["mac"]) or by_index.get(h.get("wex") or 0)
        h["ap"] = rep["label"] if rep else box_label
        h["ap_kind"] = "repeater" if rep else "box"
        if rep and h["mac"] in rep["stations"]:
            h["ssid"] = rep["stations"][h["mac"]]["ssid"]


def new_host(**kw) -> dict:
    """Appareil normalisé (toutes les clés présentes, même vides)."""
    h = {"mac": None, "ip": None, "hostname": None, "active": False, "link": None, "wifi": None,
         "rssi": None, "port": None, "wex": 0, "rate": None, "type": None, "lastseen": None}
    h.update(kw)
    return h


class RateCalc:
    """Débit moyen (kbit/s) entre deux relevés de compteurs d'octets cumulés."""

    def __init__(self):
        self.prev: tuple[float, int, int] | None = None

    def update(self, rx: int | None, tx: int | None, now: float | None = None) -> tuple[int, int]:
        now = time.monotonic() if now is None else now
        if rx is None or tx is None:
            return 0, 0
        out = (0, 0)
        if self.prev and now > self.prev[0] and rx >= self.prev[1] and tx >= self.prev[2]:
            dt = now - self.prev[0]
            out = (round((rx - self.prev[1]) * 8 / 1000 / dt), round((tx - self.prev[2]) * 8 / 1000 / dt))
        self.prev = (now, rx, tx)
        return out


# ------------------------------------------------------------------ HTTP
class Http:
    """Client bloquant (à appeler dans un thread) qui garde les cookies entre les appels."""

    def __init__(self, base: str, timeout: float = 8.0, verify: bool = False, host_header: str | None = None):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.host_header = host_header
        handlers: list = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if self.base.startswith("https"):
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)

    def request(self, method: str, path: str = "", *, form: dict | None = None, json_body=None,
                headers: dict | None = None, data: bytes | None = None) -> tuple[int, bytes]:
        hdrs = dict(headers or {})
        if self.host_header:
            hdrs["Host"] = self.host_header
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif json_body is not None:
            data = json.dumps(json_body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=hdrs)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise BoxError(f"box injoignable ({getattr(e, 'reason', e)})") from e

    def json(self, method: str, path: str = "", **kw) -> tuple[int, object]:
        status, raw = self.request(method, path, **kw)
        try:
            return status, (json.loads(raw) if raw else None)
        except ValueError:
            return status, None


# ------------------------------------------------------------------ fournisseur
class BoxProvider:
    id = ""
    label = ""
    ap_label = "Box"            # nom de la box comme point d'accès
    scheme = "http"
    auth = "password"           # password | userpass | approval (Freebox : bouton)
    default_user = ""
    experimental = True         # vrai tant que le fournisseur n'a pas été vérifié sur du matériel réel
    hint = ""                   # où trouver le mot de passe, affiché dans l'assistant
    features = ("hosts",)       # ce que ce fournisseur sait relever

    def __init__(self, host: str, http: Http | None = None):
        if not host_allowed(host):
            raise BoxError("adresse de la box refusée (IP privée ou nom de box connu uniquement)")
        self.host = host
        self.http = http or self.make_http()
        self.authenticated = False

    def make_http(self) -> Http:
        return Http(f"{self.scheme}://{self.host}")

    @classmethod
    def info(cls) -> dict:
        return {"id": cls.id, "label": cls.label, "auth": cls.auth, "default_user": cls.default_user,
                "experimental": cls.experimental, "hint": cls.hint, "features": list(cls.features)}

    @classmethod
    def probe(cls, host: str, http: Http | None = None) -> dict | None:
        """Reconnaît la box sans identifiants. Renvoie {"model": …} ou None."""
        raise NotImplementedError

    def collect(self, creds: dict) -> dict:
        raise NotImplementedError

    def logout(self) -> None:
        self.authenticated = False
