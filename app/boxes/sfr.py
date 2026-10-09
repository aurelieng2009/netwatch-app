"""Box SFR (NB6, NB7, NB8…) via son API locale `/api/1.0/` (réponses en XML).

Connexion par identifiant (« admin ») et mot de passe de la box. L'authentification est un défi :
`auth.getToken` donne un jeton, puis `auth.checkToken` reçoit HMAC-SHA256(jeton, SHA-256(identifiant))
suivi de HMAC-SHA256(jeton, SHA-256(mot de passe)). Le mot de passe ne circule donc pas en clair.

Fournisseur écrit d'après le fonctionnement de cette API (utilisée par l'intégration « SFR Box » de
Home Assistant), non vérifié sur du matériel réel. La liste des appareils (`lan.getHostsList`) n'existe
pas sur toutes les versions : si elle manque, la supervision de la ligne continue de fonctionner.
"""
from __future__ import annotations

import hashlib
import hmac
import time
import xml.etree.ElementTree as ET

from .base import BoxAuthError, BoxError, BoxProvider, Http, empty_snapshot, mac_or_none, new_host, to_int

AUTH_ERRORS = {"115", "204", "901"}
TOKEN_LIFETIME = 280


def compute_hash(token: str, username: str, password: str) -> str:
    def part(secret: str) -> str:
        digest = hashlib.sha256(secret.encode()).hexdigest()
        return hmac.new(token.encode(), digest.encode(), hashlib.sha256).hexdigest()
    return part(username) + part(password)


def parse_xml(raw: bytes | str, method: str = "") -> ET.Element:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise BoxError(f"{method} : réponse illisible") from e
    if root.get("stat") not in (None, "ok"):
        err = root.find("err")
        code = (err.get("code") if err is not None else "") or ""
        msg = (err.get("msg") if err is not None else "") or "erreur"
        if code in AUTH_ERRORS:
            raise BoxAuthError(f"{method} : accès refusé ({msg})")
        raise BoxError(f"{method} : {msg} ({code})")
    return root


def _first(root: ET.Element, tag: str) -> dict:
    el = root if root.tag == tag else root.find(f".//{tag}")
    return dict(el.attrib) if el is not None else {}


def parse_system(root: ET.Element) -> dict:
    a = _first(root, "system")
    return {"model": a.get("product_id"), "uptime": to_int(a.get("uptime")), "boots": None,
            "firmware": a.get("version_mainfirmware") or a.get("version_mainarea"), "ftth": False}


def parse_wan(root: ET.Element) -> tuple[dict, bool | None, bool]:
    a = _first(root, "wan")
    status = str(a.get("status") or "").lower()
    wan = {"ip": a.get("ip_addr"), "ip6": a.get("ipv6_addr") or None, "gateway": None, "dns": None,
           "state": "Up" if status == "up" else (status or None)}
    return wan, (status == "up") if status else None, "ftth" in str(a.get("infra") or a.get("mode") or "").lower()


def parse_hosts(root: ET.Element, wlan: ET.Element | None = None) -> list[dict]:
    rssi = {}
    for c in (wlan.iter("client") if wlan is not None else []):
        mac = mac_or_none(c.get("mac_addr") or c.get("mac"))
        if mac:
            rssi[mac] = (to_int(c.get("rssi") or c.get("signal")), c.get("wifi_band") or c.get("band"))
    out = []
    for h in root.iter("host"):
        mac = mac_or_none(h.get("mac"))
        iface = str(h.get("iface") or "").lower()
        wifi = iface.startswith("wl") or "wifi" in iface or (mac in rssi if mac else False)
        wifi = True if wifi else (False if iface else None)
        sig, band = rssi.get(mac, (None, None))
        label = None
        if wifi:
            b = str(band or "").replace("GHz", "").replace("g", "").strip()
            label = f"Wifi {b}" if b in ("2.4", "5", "6") else "Wifi"
        elif wifi is False:
            label = "Ethernet"
        out.append(new_host(
            mac=mac, ip=h.get("ip") or None, hostname=h.get("name") or None,
            active=str(h.get("status") or "").lower() == "online" or h.get("alive") == "1",
            link=label, wifi=wifi, rssi=sig if sig and sig < 0 else None, type=h.get("type") or None))
    return out


class SfrProvider(BoxProvider):
    id = "sfr"
    label = "Box SFR"
    ap_label = "Box SFR"
    scheme = "http"
    auth = "userpass"
    default_user = "admin"
    experimental = True
    hint = ("Identifiant « admin » et mot de passe d'administration de la box SFR (étiquette sous la box, "
            "ou celui que vous avez choisi).")
    features = ("hosts", "wifi")

    def __init__(self, host: str, http: Http | None = None):
        super().__init__(host, http)
        self.token: str | None = None
        self.token_at = 0.0

    def _get(self, method: str, **params) -> ET.Element:
        query = "&".join([f"method={method}"] + [f"{k}={v}" for k, v in params.items()])
        status, raw = self.http.request("GET", f"/api/1.0/?{query}")
        if status != 200:
            raise BoxError(f"{method} : HTTP {status}")
        return parse_xml(raw, method)

    def login(self, username: str, password: str) -> None:
        root = self._get("auth.getToken")
        a = _first(root, "auth")
        token = a.get("token")
        if not token or a.get("method") not in ("all", "passwd"):
            raise BoxError("la box SFR n'accepte pas ce mode de connexion")
        checked = self._get("auth.checkToken", token=token, hash=compute_hash(token, username or "admin", password))
        self.token = _first(checked, "auth").get("token")
        if not self.token:
            raise BoxAuthError("identifiant ou mot de passe refusé par la box SFR")
        self.token_at, self.authenticated = time.monotonic(), True

    def call(self, creds: dict, method: str) -> ET.Element:
        if not self.token or time.monotonic() - self.token_at > TOKEN_LIFETIME:
            self.login(creds.get("username") or "admin", creds.get("password") or "")
        try:
            return self._get(method, token=self.token)
        except BoxAuthError:
            self.token, self.authenticated = None, False
            self.login(creds.get("username") or "admin", creds.get("password") or "")
            return self._get(method, token=self.token)

    @classmethod
    def probe(cls, host: str, http: Http | None = None) -> dict | None:
        try:
            p = cls(host, http)
            root = p._get("system.getInfo")
        except BoxError:
            return None
        info = parse_system(root)
        return {"model": info["model"]} if info["model"] else None

    def logout(self) -> None:
        self.token, self.authenticated = None, False

    def collect(self, creds: dict) -> dict:
        snap = empty_snapshot()
        try:                                              # public : pas de mot de passe nécessaire
            snap["device"] = parse_system(self._get("system.getInfo"))
        except BoxError as e:
            snap["endpoints"]["system.getInfo"] = str(e)
        try:
            wan, up, ftth = parse_wan(self._get("wan.getInfo"))
            snap["wan"], snap["summary"]["internet_up"], snap["device"]["ftth"] = wan, up, ftth
        except BoxError as e:
            snap["endpoints"]["wan.getInfo"] = str(e)
        if not creds.get("password"):
            return snap
        try:
            hosts_root = self.call(creds, "lan.getHostsList")
            wlan = None
            try:
                wlan = self.call(creds, "wlan.getClientList")
            except BoxAuthError:
                raise
            except BoxError as e:
                snap["endpoints"]["wlan.getClientList"] = str(e)
            snap["hosts"] = parse_hosts(hosts_root, wlan)
            for h in snap["hosts"]:
                h["ap"], h["ap_kind"] = self.ap_label, "box"
        except BoxAuthError as e:
            snap["auth_error"] = str(e)
        except BoxError as e:
            snap["endpoints"]["lan.getHostsList"] = str(e)
        return snap
