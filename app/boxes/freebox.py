"""Freebox (Free) via l'API locale Freebox OS (`/api/latest/`).

Pas de mot de passe : NetWatch demande une autorisation (« app token ») que l'on confirme **en
appuyant sur la flèche de la façade de la Freebox**. Le jeton obtenu est chiffré par le coffre.
Les sessions s'ouvrent ensuite par un défi HMAC-SHA1, sans que le jeton ne circule.

Fournisseur écrit d'après la documentation officielle (dev.freebox.fr/sdk/os), non vérifié sur du
matériel réel. Certaines lectures (Wi-Fi, répéteurs) demandent d'accorder des droits supplémentaires
à l'application dans Freebox OS (Paramètres → Gestion des accès → Applications).
"""
from __future__ import annotations

import hashlib
import hmac
import time

from ..wifi import DFS_RANGE
from .base import (BoxApprovalRequired, BoxAuthError, BoxError, BoxProvider, Http, empty_snapshot, mac_or_none,
                   new_host, to_int)

APP_ID = "fr.netwatch.supervision"
APP_NAME = "NetWatch"
API = "/api/latest"
_BANDS = {"2g4": "2.4", "2d4g": "2.4", "5g": "5", "6g": "6"}
_SECURITY = {"wpa2_psk": "WPA2", "wpa3_sae": "WPA3", "wpa3_sae_transition": "WPA2/WPA3", "wpa_psk": "WPA",
             "wpa2_wpa3_psk": "WPA2/WPA3", "open": "ouvert"}


def _band(raw) -> str | None:
    s = str(raw or "").lower().replace(".", "")
    if s in _BANDS:
        return _BANDS[s]
    for token, label in (("2", "2.4"), ("5", "5"), ("6", "6")):
        if s.startswith(token):
            return label
    return None


def parse_system(result) -> dict:
    r = result if isinstance(result, dict) else {}
    model = (r.get("model_info") or {}).get("pretty_name") or r.get("board_name")
    return {"model": model, "uptime": to_int(r.get("uptime_val")), "boots": None,
            "firmware": r.get("firmware_version"), "ftth": False}


def parse_connection(result) -> tuple[dict, dict, dict | None, bool]:
    """(wan, résumé, stats, fibre) à partir de `connection/`."""
    r = result if isinstance(result, dict) else {}
    up = str(r.get("state") or "").lower() == "up"
    wan = {"ip": r.get("ipv4"), "ip6": r.get("ipv6"), "gateway": None, "dns": None,
           "state": "Up" if up else (r.get("state") or None)}
    rx, tx = to_int(r.get("bytes_down")), to_int(r.get("bytes_up"))
    stats = None
    if rx is not None and tx is not None:
        bw_down, bw_up = to_int(r.get("bandwidth_down")), to_int(r.get("bandwidth_up"))
        rx_kbps = round((to_int(r.get("rate_down"), 0) or 0) * 8 / 1000)        # octets/s → kbit/s
        tx_kbps = round((to_int(r.get("rate_up"), 0) or 0) * 8 / 1000)
        stats = {"rx_bytes": rx, "tx_bytes": tx, "rx_kbps": rx_kbps, "tx_kbps": tx_kbps,
                 "rx_occ": round(rx_kbps * 100000 / bw_down) if bw_down else 0,
                 "tx_occ": round(tx_kbps * 100000 / bw_up) if bw_up else 0,
                 "rx_contract_kbps": bw_down // 1000 if bw_down else None,
                 "tx_contract_kbps": bw_up // 1000 if bw_up else None}
    return wan, up if r.get("state") else None, stats, str(r.get("media") or "").lower() == "ftth"


def parse_hosts(result, now: float | None = None) -> tuple[list[dict], list[dict]]:
    """Appareils du réseau local, puis répéteurs Wi-Fi déduits du point d'accès de chaque appareil."""
    now = time.time() if now is None else now
    raw = [h for h in (result or []) if isinstance(h, dict)]
    names_by_mac = {}
    for h in raw:
        l2 = h.get("l2ident") or {}
        mac = mac_or_none(l2.get("id")) if l2.get("type") in (None, "mac_address") else None
        if mac:
            names_by_mac[mac] = h.get("primary_name")
    hosts, reps = [], {}
    for h in raw:
        l2 = h.get("l2ident") or {}
        mac = mac_or_none(l2.get("id")) if l2.get("type") in (None, "mac_address") else None
        v4 = [c for c in h.get("l3connectivities") or [] if c.get("af") == "ipv4"]
        v4.sort(key=lambda c: not c.get("active"))
        ap = h.get("access_point") or {}
        ctype = str(ap.get("connectivity_type") or "").lower()
        wi = ap.get("wifi_information") or {}
        band = _band(wi.get("band"))
        wifi = True if ctype == "wifi" else False if ctype == "ethernet" else None
        link = f"Wifi {band}" if wifi and band else "Wifi" if wifi else "Ethernet" if wifi is False else None
        last = to_int(h.get("last_activity"))
        host = new_host(
            mac=mac, ip=v4[0]["addr"] if v4 else None, hostname=h.get("primary_name") or None,
            active=bool(h.get("active")), link=link, wifi=wifi, rssi=to_int(wi.get("signal")),
            type=h.get("host_type") or None, lastseen=max(int(now - last), 0) if last else None)
        ap_mac = mac_or_none(ap.get("mac"))
        if ap_mac and ap_mac != mac and "repeater" in str(ap.get("type") or "").lower():
            name = names_by_mac.get(ap_mac) or f"Répéteur {ap_mac.replace(':', '')[-4:].upper()}"
            rep = reps.setdefault(ap_mac, {"index": None, "mac": ap_mac, "label": name, "stations": {}})
            if mac:
                rep["stations"][mac] = {"ssid": wi.get("ssid"), "rssi": to_int(wi.get("signal"))}
            host["ap"], host["ap_kind"], host["ssid"] = name, "repeater", wi.get("ssid")
        else:
            host["ap"], host["ap_kind"] = "Freebox", "box"
            if wi.get("ssid"):
                host["ssid"] = wi.get("ssid")
        hosts.append(host)
    return hosts, list(reps.values())


def parse_radios(aps, bss) -> dict | None:
    """Canaux, largeurs et sécurité de chaque bande (jamais les clés Wi-Fi)."""
    if not isinstance(aps, list) or not aps:
        return None
    ssids: dict = {}
    for b in bss if isinstance(bss, list) else []:
        cfg = b.get("config") or {}
        ssids.setdefault(b.get("phy_id"), {"ssid": cfg.get("ssid"),
                                             "security": _SECURITY.get(str(cfg.get("encryption")), cfg.get("encryption")),
                                             "enabled": bool(cfg.get("enabled", True))})
    bands = {}
    for ap in aps:
        st, cfg = ap.get("status") or {}, ap.get("config") or {}
        label = _band(cfg.get("band") or (ap.get("capabilities") or {}).get("band") or ap.get("name"))
        if not label or label in bands:
            continue
        ch = to_int(st.get("primary_channel"))
        s = ssids.get(ap.get("id")) or {}
        bands[label] = {"enabled": str(st.get("state") or "").lower() in ("active", "starting", "dfs"),
                        "channel": ch, "width": to_int(st.get("channel_width")), "standard": None,
                        "ssid": s.get("ssid"), "security": s.get("security"),
                        "dfs": label == "5" and ch in DFS_RANGE}
    return {"bands": bands, "mlo": None, "unified": len({b["ssid"] for b in bands.values() if b["ssid"]}) == 1} \
        if bands else None


class FreeboxProvider(BoxProvider):
    id = "freebox"
    label = "Freebox (Free)"
    ap_label = "Freebox"
    scheme = "http"
    auth = "approval"
    experimental = True
    hint = ("Aucun mot de passe : NetWatch demande une autorisation, à confirmer en appuyant sur la flèche "
            "de la façade de la Freebox Server.")
    features = ("hosts", "stats", "repeaters", "radios", "wifi")

    def __init__(self, host: str, http: Http | None = None):
        super().__init__(host, http)
        self.session_token: str | None = None

    # -- appels
    @staticmethod
    def _result(status: int, body, path: str):
        if isinstance(body, dict) and body.get("success") is True:
            return body.get("result")
        code = body.get("error_code") if isinstance(body, dict) else None
        msg = body.get("msg") if isinstance(body, dict) else None
        if status == 403 and code in ("auth_required", "invalid_session"):
            raise BoxAuthError("session expirée")
        if status == 403 and code in ("insufficient_rights", "denied_from_external_ip"):
            raise BoxError(f"{path} : droit insuffisant pour l'application NetWatch (voir Freebox OS → "
                           "Paramètres → Gestion des accès → Applications)")
        raise BoxError(f"{path} : HTTP {status}{' (' + msg + ')' if msg else ''}")

    def _get(self, path: str):
        hdrs = {"X-Fbx-App-Auth": self.session_token} if self.session_token else {}
        status, body = self.http.json("GET", f"{API}/{path}", headers=hdrs)
        return self._result(status, body, path)

    def _open_session(self, app_token: str) -> None:
        status, body = self.http.json("GET", f"{API}/login/")
        challenge = (self._result(status, body, "login/") or {}).get("challenge")
        if not challenge:
            raise BoxError("la Freebox n'a pas fourni de défi de connexion")
        pw = hmac.new(app_token.encode(), challenge.encode(), hashlib.sha1).hexdigest()
        status, body = self.http.json("POST", f"{API}/login/session/", json_body={"app_id": APP_ID, "password": pw})
        if status == 403 or (isinstance(body, dict) and body.get("success") is False):
            raise BoxAuthError("autorisation refusée ou révoquée par la Freebox : relancez l'appairage")
        res = self._result(status, body, "login/session/") or {}
        self.session_token = res.get("session_token")
        if not self.session_token:
            raise BoxError("la Freebox n'a pas ouvert de session")
        self.authenticated = True

    def _authed(self, app_token: str, path: str):
        if not self.session_token:
            self._open_session(app_token)
        try:
            return self._get(path)
        except BoxAuthError:
            self.session_token, self.authenticated = None, False
            self._open_session(app_token)
            return self._get(path)

    # -- autorisation par bouton
    def request_authorization(self) -> dict:
        """Demande une autorisation. À confirmer sur la façade ; renvoie {"app_token", "track_id"}."""
        status, body = self.http.json("POST", f"{API}/login/authorize/", json_body={
            "app_id": APP_ID, "app_name": APP_NAME, "app_version": "1", "device_name": "NetWatch"})
        res = self._result(status, body, "login/authorize/") or {}
        if not res.get("app_token"):
            raise BoxError("la Freebox n'a pas fourni de jeton")
        return {"app_token": res["app_token"], "track_id": res.get("track_id")}

    def authorization_status(self, track_id) -> str:
        """pending | granted | denied | timeout | unknown"""
        status, body = self.http.json("GET", f"{API}/login/authorize/{track_id}")
        return str((self._result(status, body, "login/authorize/") or {}).get("status") or "unknown")

    # -- détection / relevé
    @classmethod
    def probe(cls, host: str, http: Http | None = None) -> dict | None:
        try:
            p = cls(host, http)
            status, body = p.http.json("GET", "/api_version")
        except BoxError:
            return None
        if status == 200 and isinstance(body, dict) and (
                "api_version" in body and ("freebox" in str(body.get("device_name", "")).lower()
                                           or "freebox" in str(body.get("device_type", "")).lower()
                                           or "freebox" in str(body.get("api_domain", "")).lower())):
            return {"model": body.get("box_model_name") or body.get("device_name")}
        return None

    def logout(self) -> None:
        if self.session_token:
            try:
                self.http.request("POST", f"{API}/login/logout/", headers={"X-Fbx-App-Auth": self.session_token},
                                  data=b"")
            except BoxError:
                pass
        self.session_token, self.authenticated = None, False

    def collect(self, creds: dict) -> dict:
        token = creds.get("token")
        if not token:
            raise BoxApprovalRequired("autorisation de la Freebox requise")
        snap = empty_snapshot()
        snap["device"] = parse_system(self._authed(token, "system/"))
        wan, up, stats, ftth = parse_connection(self._authed(token, "connection/"))
        snap["wan"], snap["stats"] = wan, stats
        snap["summary"]["internet_up"] = up
        snap["device"]["ftth"] = ftth
        try:
            snap["hosts"], snap["repeaters"] = parse_hosts(self._authed(token, "lan/browser/pub/"))
        except BoxAuthError:
            raise
        except BoxError as e:
            snap["endpoints"]["lan/browser/pub"] = str(e)
        try:
            snap["radios"] = parse_radios(self._authed(token, "wifi/ap/"), self._authed(token, "wifi/bss/"))
        except BoxAuthError:
            raise
        except BoxError as e:
            snap["endpoints"]["wifi/ap"] = str(e)
        return snap
