"""Livebox (Orange) via l'interface « sysbus » (`/ws`), celle qu'utilise l'interface web de la box.

Connexion par identifiant (« admin ») et mot de passe, imprimé sous la box. La box répond par un
`contextID` qu'on renvoie ensuite dans l'en-tête `X-Context`. Les cookies sont gardés entre les appels.

Fournisseur écrit d'après le fonctionnement public de cette interface (utilisée par les intégrations
communautaires), non vérifié sur du matériel réel : les champs absents restent vides plutôt que de
faire échouer le relevé, et chaque lecture refusée est signalée dans `endpoints`.
"""
from __future__ import annotations

from .base import (BoxAuthError, BoxError, BoxProvider, Http, RateCalc, empty_snapshot, mac_or_none, new_host,
                   to_int)

CT = "application/x-sah-ws-1-call+json; charset=UTF-8"


def _val(body, key: str = "status"):
    """Les réponses sont `{"status": …}`, `{"data": …}` ou la même chose sous `{"result": …}`."""
    if not isinstance(body, dict):
        return None
    inner = body.get("result") if isinstance(body.get("result"), dict) else body
    return inner.get(key) if key in inner else None


def parse_device_info(body) -> dict:
    d = _val(body) or {}
    d = d if isinstance(d, dict) else {}
    return {"model": d.get("ProductClass") or d.get("ModelName"), "uptime": to_int(d.get("UpTime")),
            "boots": to_int(d.get("NumberOfReboots")), "firmware": d.get("SoftwareVersion"), "ftth": False}


def parse_wan(body) -> tuple[dict, bool | None, bool]:
    d = _val(body, "data") or _val(body) or {}
    d = d if isinstance(d, dict) else {}
    state = str(d.get("WanState") or d.get("LinkState") or "").lower()
    wan = {"ip": d.get("IPAddress"), "ip6": d.get("IPv6Address"), "gateway": d.get("RemoteGateway"),
           "dns": d.get("DNSServers"), "state": "Up" if state == "up" else (state or None)}
    return wan, (state == "up") if state else None, "ftth" in str(d.get("LinkType") or "").lower()


def _band_of_device(d: dict) -> str | None:
    raw = str(d.get("OperatingFrequencyBand") or d.get("Frequency") or "").lower()
    for token, label in (("2.4", "2.4"), ("5", "5"), ("6", "6")):
        if raw.startswith(token):
            return label
    iface = str(d.get("InterfaceName") or d.get("Layer2Interface") or "").lower()
    return {"wl0": "2.4", "wl1": "5", "wl2": "6"}.get(iface[:3])


def parse_devices(body) -> list[dict]:
    items = _val(body)
    if isinstance(items, dict):
        items = items.get("list") or list(items.values())
    out = []
    for d in items if isinstance(items, list) else []:
        if not isinstance(d, dict):
            continue
        tags = str(d.get("Tags") or "").lower()
        iface = str(d.get("InterfaceName") or d.get("Layer2Interface") or "").lower()
        wifi = "wifi" in tags or iface.startswith("wl") or "wifi" in str(d.get("Technology") or "").lower()
        if not wifi and not (iface.startswith("eth") or "ethernet" in tags or "eth" in iface):
            wifi_known = None
        else:
            wifi_known = wifi
        band = _band_of_device(d) if wifi_known else None
        sig = to_int(d.get("SignalStrength"))
        out.append(new_host(
            mac=mac_or_none(d.get("PhysAddress") or d.get("Key")), ip=d.get("IPAddress") or None,
            hostname=d.get("Name") or None, active=bool(d.get("Active")),
            link=(f"Wifi {band}" if band else "Wifi") if wifi_known else "Ethernet" if wifi_known is False else None,
            wifi=wifi_known, rssi=sig if sig and sig < 0 else None, type=d.get("DeviceType") or None,
            lastseen=None))
    return out


class LiveboxProvider(BoxProvider):
    id = "livebox"
    label = "Livebox (Orange)"
    ap_label = "Livebox"
    scheme = "http"
    auth = "userpass"
    default_user = "admin"
    experimental = True
    hint = ("Identifiant « admin » et mot de passe d'administration de la Livebox (étiquette sous la box, "
            "ou celui que vous avez choisi).")
    features = ("hosts", "stats", "wifi")

    def __init__(self, host: str, http: Http | None = None):
        super().__init__(host, http)
        self.context: str | None = None
        self.rates = RateCalc()

    def _post(self, service: str, method: str, params: dict | None = None, *, login: dict | None = None):
        headers = {"Content-Type": CT}
        if login is not None:
            headers["Authorization"] = "X-Sah-Login"
        elif self.context:
            headers["X-Context"] = self.context
        status, body = self.http.json("POST", "/ws", headers=headers, json_body={
            "service": service, "method": method, "parameters": login if login is not None else (params or {})})
        return status, body

    def login(self, username: str, password: str) -> None:
        status, body = self._post("sah.Device.Information", "createContext", login={
            "applicationName": "webui", "username": username or "admin", "password": password})
        data = _val(body, "data")
        if status in (401, 403) or not isinstance(data, dict) or not data.get("contextID"):
            raise BoxAuthError("identifiant ou mot de passe refusé par la Livebox")
        self.context, self.authenticated = data["contextID"], True

    def call(self, creds: dict, service: str, method: str, params: dict | None = None):
        """Appel authentifié ; on se reconnecte une fois si le contexte a expiré."""
        for attempt in (0, 1):
            if not self.context:
                self.login(creds.get("username") or "admin", creds.get("password") or "")
            status, body = self._post(service, method, params)
            expired = status in (401, 403) or (isinstance(body, dict) and body.get("errors")
                                                and "permission" in str(body.get("errors")).lower())
            if expired and attempt == 0:
                self.context, self.authenticated = None, False
                continue
            if status != 200 or not isinstance(body, dict):
                raise BoxError(f"{service}.{method} : HTTP {status}")
            return body
        raise BoxAuthError("session refusée par la Livebox")

    @classmethod
    def probe(cls, host: str, http: Http | None = None) -> dict | None:
        try:
            p = cls(host, http)
            status, raw = p.http.request("GET", "/")
        except BoxError:
            return None
        text = raw.decode("utf-8", "ignore").lower()
        return {"model": "Livebox"} if status == 200 and "livebox" in text else None

    def logout(self) -> None:
        self.context, self.authenticated = None, False

    def collect(self, creds: dict) -> dict:
        snap = empty_snapshot()
        if not creds.get("password"):
            snap["endpoints"]["login"] = "mot de passe requis"
            return snap
        try:
            snap["device"] = parse_device_info(self.call(creds, "DeviceInfo", "get"))
        except BoxAuthError as e:
            snap["auth_error"] = str(e)
            return snap
        except BoxError as e:
            snap["endpoints"]["DeviceInfo.get"] = str(e)
        try:
            wan, up, ftth = parse_wan(self.call(creds, "NMC", "getWANStatus"))
            snap["wan"], snap["summary"]["internet_up"], snap["device"]["ftth"] = wan, up, ftth
        except BoxError as e:
            snap["endpoints"]["NMC.getWANStatus"] = str(e)
        try:
            st = _val(self.call(creds, "NeMo.Intf.data", "getNetDevStats")) or {}
            rx, tx = to_int(st.get("RxBytes")), to_int(st.get("TxBytes"))
            if rx is not None and tx is not None:
                rx_kbps, tx_kbps = self.rates.update(rx, tx)
                snap["stats"] = {"rx_bytes": rx, "tx_bytes": tx, "rx_kbps": rx_kbps, "tx_kbps": tx_kbps,
                                 "rx_occ": 0, "tx_occ": 0, "rx_contract_kbps": None, "tx_contract_kbps": None}
        except BoxError as e:
            snap["endpoints"]["NeMo.Intf.data.getNetDevStats"] = str(e)
        hosts = None
        for params in ({"expression": "lan and not self"}, None):
            try:
                hosts = parse_devices(self.call(creds, "Devices", "get", params))
                if hosts:
                    break
            except BoxError as e:
                snap["endpoints"]["Devices.get"] = str(e)
        if hosts is not None:
            snap["endpoints"].pop("Devices.get", None)
            for h in hosts:
                h["ap"], h["ap_kind"] = self.ap_label, "box"
            snap["hosts"] = hosts
        return snap
