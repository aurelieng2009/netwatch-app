"""Bbox (Bouygues Telecom) via son API locale `/api/v1`. Vérifié sur une Bbox Wi-Fi 7 (F@st5696b).

Sans authentification, la box expose l'état de la ligne (`device`, `summary`, `wan/ip`,
`wan/ip/stats`, `lan/stats`). Avec le mot de passe administrateur (aucun identifiant : la box
n'en a pas), on obtient en plus les appareils (`hosts`), les répéteurs et la configuration radio.
"""
from __future__ import annotations

from ..wifi import parse_radios
from .base import (BoxAuthError, BoxError, BoxProvider, Http, assign_access_points, empty_snapshot,
                   mac_or_none, to_int)

DEFAULT_HOST = "mabbox.bytel.fr"
INTERNET_UP = 2


def _unwrap(body, key: str):
    """Les réponses sont `[{"<clé>": {...}}]` (parfois sans la liste)."""
    if isinstance(body, list):
        body = body[0] if body else None
    return body.get(key) if isinstance(body, dict) else None


def parse_device(body) -> dict:
    d = _unwrap(body, "device") or {}
    return {
        "model": d.get("modelname"), "uptime": to_int(d.get("uptime")),
        "boots": to_int(d.get("numberofboots")),
        "firmware": (d.get("running") or {}).get("version") or (d.get("main") or {}).get("version"),
        "ftth": bool((d.get("using") or {}).get("ftth")),
    }


def parse_summary(body) -> dict:
    if isinstance(body, list):
        body = body[0] if body else {}
    body = body if isinstance(body, dict) else {}
    wl = body.get("wireless") or {}
    state = to_int((body.get("internet") or {}).get("state"))
    return {
        "internet_up": None if state is None else state == INTERNET_UP,
        "wifi_radio": bool(to_int(wl.get("radio"), 0)),
        "wifi_guest": bool(to_int(wl.get("guestenable"), 0)),
    }


def parse_wan_ip(body) -> dict:
    ip = (_unwrap(body, "wan") or {}).get("ip") or {}
    return {"ip": ip.get("address"), "ip6": ((ip.get("ip6address") or [{}])[0]).get("ipaddress"),
            "gateway": ip.get("gateway"), "dns": ip.get("dnsservers"), "state": ip.get("state")}


def parse_wan_stats(body) -> dict | None:
    """Compteurs et débits instantanés du lien WAN (débits en kbit/s, octets cumulés)."""
    st = ((_unwrap(body, "wan") or {}).get("ip") or {}).get("stats")
    if not st:
        return None
    rx, tx = st.get("rx") or {}, st.get("tx") or {}
    return {
        "rx_bytes": to_int(rx.get("bytes")), "tx_bytes": to_int(tx.get("bytes")),
        "rx_kbps": to_int(rx.get("bandwidth"), 0), "tx_kbps": to_int(tx.get("bandwidth"), 0),
        "rx_occ": to_int(rx.get("occupation"), 0), "tx_occ": to_int(tx.get("occupation"), 0),
        "rx_contract_kbps": to_int(rx.get("contractualBandwidth")),
        "tx_contract_kbps": to_int(tx.get("contractualBandwidth")),
    }


def parse_hosts(body) -> list[dict]:
    """Normalise la liste des appareils connus de la box."""
    out = []
    for h in (_unwrap(body, "hosts") or {}).get("list") or []:
        if not isinstance(h, dict):
            continue
        link = str(h.get("link") or "")
        wl = h.get("wireless") or h.get("wifi") or {}
        eth = h.get("ethernet") or {}
        out.append({
            "mac": mac_or_none(h.get("macaddress")), "ip": h.get("ipaddress") or None,
            "hostname": h.get("hostname") or None,
            "active": bool(to_int(h.get("active"), 0)), "link": link or None,
            "wifi": link.lower().startswith("wi") if link else None,
            "rssi": to_int(wl.get("rssi0")) if isinstance(wl, dict) else None,
            "port": to_int(eth.get("physicalport")) if isinstance(eth, dict) else None,
            "wex": to_int(wl.get("wexindex"), 0) if isinstance(wl, dict) else 0,
            "rate": to_int(wl.get("rate")) if isinstance(wl, dict) else None,
            "type": h.get("devicetype") or None, "lastseen": to_int(h.get("lastseen")),
        })
    return out


def parse_repeaters(body) -> list[dict]:
    """Répéteurs Wi-Fi de la box, avec les stations (MAC) qui leur sont associées."""
    if isinstance(body, list):
        body = body[0] if body else {}
    body = body if isinstance(body, dict) else {}
    out = []
    for r in (body.get("repeater") or body).get("list") or []:
        if not isinstance(r, dict):
            continue
        mac = mac_or_none(r.get("macaddress"))
        stations = {}
        for s in r.get("stations") or []:
            smac = mac_or_none(s.get("macaddress"))
            if smac:
                stations[smac] = {"ssid": s.get("ssid"), "rssi": to_int(s.get("rssi"))}
        out.append({"index": to_int(r.get("hostindex")), "mac": mac, "stations": stations,
                    # même suffixe que dans l'interface de la box : « Répéteur -8070 »
                    "label": f"Répéteur {mac.replace(':', '')[-4:].upper()}" if mac else "Répéteur"})
    return out


class BouyguesProvider(BoxProvider):
    id = "bouygues"
    label = "Bbox (Bouygues Telecom)"
    ap_label = "Bbox"
    scheme = "https"
    auth = "password"
    experimental = False
    hint = ("Mot de passe de l'interface d'administration (mabbox.bytel.fr). Il n'y a pas d'identifiant : "
            "la box n'en demande pas.")
    features = ("hosts", "stats", "repeaters", "radios", "wifi")

    def make_http(self) -> Http:
        # Appelée par son IP, la box répond par une redirection 302 vers mabbox.bytel.fr ; un POST
        # (le login) devient alors un GET et échoue en 404. L'en-tête Host évite la redirection.
        return Http(f"https://{self.host}/api/v1", host_header=DEFAULT_HOST)

    def get(self, path: str):
        status, body = self.http.json("GET", "/" + path)
        if status == 401:
            raise BoxAuthError("authentification requise")
        if status != 200:
            raise BoxError(f"{path} : HTTP {status}")
        return body

    def login(self, password: str) -> None:
        status, body = self.http.json("POST", "/login", form={"password": password, "remember": "1"})
        if status == 200:
            self.authenticated = True
            return
        if status in (401, 403):
            raise BoxAuthError("mot de passe refusé par la box")
        reason = ""
        if isinstance(body, dict):
            errs = (body.get("exception") or {}).get("errors") or [{}]
            reason = errs[0].get("reason") or ""
        raise BoxError(f"connexion refusée (HTTP {status}{' : ' + reason if reason else ''})")

    def logout(self) -> None:
        try:
            self.http.request("POST", "/logout", form={})
        except BoxError:
            pass
        self.authenticated = False

    @classmethod
    def probe(cls, host: str, http: Http | None = None) -> dict | None:
        try:
            p = cls(host, http)
            d = parse_device(p.get("device"))
        except BoxError:
            return None
        return {"model": d["model"]} if d["model"] else None

    def _authed(self, password: str, path: str):
        """GET authentifié. La session est conservée d'un relevé à l'autre (chaque connexion remplit le
        journal de la box) ; si elle a expiré, on se reconnecte une fois."""
        if not self.authenticated:
            self.login(password)
        try:
            return self.get(path)
        except BoxAuthError:
            self.authenticated = False
            self.login(password)
            return self.get(path)

    def collect(self, creds: dict) -> dict:
        password = creds.get("password")
        snap = empty_snapshot()
        snap["device"] = parse_device(self.get("device"))
        snap["summary"] = parse_summary(self.get("summary"))
        snap["wan"] = parse_wan_ip(self.get("wan/ip"))
        try:
            snap["stats"] = parse_wan_stats(self.get("wan/ip/stats"))
        except BoxError as e:
            snap["endpoints"]["wan/ip/stats"] = str(e)
        if password:
            try:
                snap["hosts"] = parse_hosts(self._authed(password, "hosts"))
                try:
                    snap["repeaters"] = parse_repeaters(self._authed(password, "wireless/repeater"))
                except BoxError as e:
                    snap["endpoints"]["wireless/repeater"] = str(e)
                assign_access_points(snap["hosts"], snap.get("repeaters") or [], self.ap_label)
                try:
                    snap["radios"] = parse_radios(self._authed(password, "wireless"))
                except BoxError as e:
                    snap["endpoints"]["wireless"] = str(e)
            except BoxAuthError as e:
                snap["auth_error"] = str(e)
            except BoxError as e:
                snap["endpoints"]["hosts"] = str(e)
        return snap
