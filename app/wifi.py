"""Suivi de la qualité Wi-Fi à partir des relevés de la box.

À chaque relevé de la box, on enregistre pour chaque appareil Wi-Fi actif son point d'accès,
sa bande et son signal, et on tient des « sessions » : une session dure tant que l'appareil reste
associé au même point d'accès sur la même bande. Elle se termine par :
  drop  l'appareil a disparu de la box (coupure Wi-Fi vue par la box, pas un simple ping perdu)
  roam  il est passé d'un point d'accès à un autre
  band  il est resté sur le même point d'accès mais a changé de bande
  gap   NetWatch n'a plus interrogé la box (on ignore ces trous)
Le signal relevé juste avant un « drop » distingue un problème de couverture (signal faible)
d'un problème de réglage ou d'économie d'énergie (signal fort).
"""
from __future__ import annotations

import json
import re

from .db import DB

WEAK_RSSI = -75           # en dessous : couverture insuffisante
DFS_RANGE = range(52, 145)
MIN_SPAN_S = 3600         # il faut au moins 1 h de relevés pour poser un diagnostic
MIN_CONNECTED_S = 1800


def _num(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n or None          # la box renvoie 0 quand le signal est inconnu


def band_of(link: str | None) -> str | None:
    """« Wifi 2.4 » → 2.4, « Wifi 5 » → 5, « Wifi 6 » → 6, « Wifi MLO » → MLO."""
    m = re.search(r"(mlo|\d+(?:\.\d)?)\s*$", (link or "").strip(), re.I)
    if not m:
        return None
    return "MLO" if m.group(1).lower() == "mlo" else m.group(1)


# ------------------------------------------------------------------ configuration radio
def parse_radios(body) -> dict | None:
    """Canaux, largeurs et sécurité de chaque bande (jamais les mots de passe)."""
    if isinstance(body, list):
        body = body[0] if body else None
    w = (body or {}).get("wireless") if isinstance(body, dict) else None
    if not isinstance(w, dict):
        return None
    radio, ssid = w.get("radio") or {}, w.get("ssid") or {}
    bands = {}
    for key, label in (("24", "2.4"), ("5", "5"), ("6", "6")):
        r, s = radio.get(key) or {}, ssid.get(key) or {}
        if not r:
            continue
        ch = _num(r.get("current_channel"))
        bands[label] = {
            "enabled": bool(r.get("enable")), "channel": ch, "width": _num(r.get("current_bandwidth")),
            "standard": r.get("standard"), "ssid": s.get("id"),
            "security": (s.get("security") or {}).get("protocol"),
            "dfs": label == "5" and ch in DFS_RANGE,
        }
    mlo = ssid.get("mlo") or {}
    return {
        "bands": bands,
        "mlo": {"enabled": bool(mlo.get("enable")), "ssid": mlo.get("id"),
                "security": (mlo.get("security") or {}).get("protocol")} if mlo else None,
        "unified": bool(w.get("unified")),
    }


def recommendations(cfg: dict | None) -> list[dict]:
    """Réglages de la box connus pour provoquer des coupures Wi-Fi."""
    if not cfg:
        return []
    out = []
    b = cfg["bands"]
    five, six, two = b.get("5"), b.get("6"), b.get("2.4")
    if five and five["enabled"] and five["dfs"]:
        out.append({"level": "warning", "code": "dfs", "title": f"5 GHz sur un canal radar (DFS) : {five['channel']}",
                    "detail": "Si la box détecte un radar, elle doit quitter le canal : tous les appareils 5 GHz "
                              "sont alors coupés plusieurs secondes, voire minutes. Un canal 36 à 48 n'est pas "
                              "concerné."})
    if five and five["enabled"] and (five["width"] or 0) >= 160:
        out.append({"level": "warning", "code": "width160",
                    "title": "5 GHz en 160 MHz",
                    "detail": "Le 160 MHz est très sensible aux interférences et à la distance, et certains "
                              "téléphones Android le gèrent mal. Le 80 MHz est nettement plus stable."})
    secs = {x["security"] for x in (two, five, six) if x and x["enabled"] and x["security"]}
    names = {x["ssid"] for x in (two, five, six) if x and x["enabled"] and x["ssid"]}
    if len(names) == 1 and len(secs) > 1:
        out.append({"level": "info", "code": "mixed_security",
                    "title": f"Même nom « {next(iter(names))} » sur plusieurs bandes avec des sécurités différentes "
                             f"({' / '.join(sorted(secs))})",
                    "detail": "Les téléphones hésitent parfois entre bandes (et entre WPA2 et WPA3) quand elles "
                              "partagent un nom. Séparer les noms par bande, ou n'utiliser que le réseau MLO, "
                              "évite ces va-et-vient."})
    if six and six["enabled"] and (six["width"] or 0) >= 320:
        out.append({"level": "info", "code": "width320", "title": "6 GHz en 320 MHz",
                    "detail": "Très rapide mais de faible portée : un téléphone qui s'y accroche perd vite le "
                              "signal en s'éloignant ou derrière un mur."})
    if two and two["enabled"] and two["channel"] not in (None, 1, 6, 11):
        out.append({"level": "info", "code": "channel24",
                    "title": f"2,4 GHz sur le canal {two['channel']}",
                    "detail": "Seuls les canaux 1, 6 et 11 ne se chevauchent pas : sur les autres, le réseau "
                              "gêne ses voisins et en subit les interférences."})
    return out


# ------------------------------------------------------------------ sessions
class WifiTracker:
    def __init__(self, db: DB):
        self.db = db
        self.open: dict[str, dict] = {r["mac"]: r for r in db.q("SELECT * FROM wifi_sessions WHERE end IS NULL")}
        self.last_update = int(db.get_meta("wifi_last_update") or 0)

    def update(self, hosts: list[dict], now: int, max_gap: int = 180) -> dict:
        """Intègre un relevé. Retourne les compteurs (ouvertures, coupures, changements) pour les tests."""
        stats = {"opened": 0, "drops": 0, "roams": 0, "bands": 0}
        cur: dict[str, dict] = {}
        for h in hosts:
            if h.get("mac") and h.get("wifi") and h.get("active"):
                cur[h["mac"]] = h          # l'entrée active l'emporte sur les entrées fantômes
        if self.last_update and now - self.last_update > max_gap:
            for mac in list(self.open):
                self._close(mac, self.open[mac]["last_ts"], "gap")
        for mac in list(self.open):
            if mac not in cur:
                self._close(mac, self.open[mac]["last_ts"], "drop")
                stats["drops"] += 1
        rows = []
        for mac, h in cur.items():
            band, ap, rssi = band_of(h.get("link")), h.get("ap") or "Box", _num(h.get("rssi"))
            s = self.open.get(mac)
            if s and (s["ap"] != ap or s["band"] != band):
                reason = "roam" if s["ap"] != ap else "band"
                self._close(mac, now, reason)
                stats["roams" if reason == "roam" else "bands"] += 1
                s = None
            if s is None:
                self._open(mac, ap, band, h.get("link"), rssi, now)
                stats["opened"] += 1
            else:
                self._touch(s, rssi, now)
            rows.append((now, mac, ap, band, h.get("link"), rssi, _num(h.get("rate"))))
        self.db.xmany("INSERT OR REPLACE INTO wifi_samples(ts, mac, ap, band, link, rssi, rate) "
                      "VALUES(?,?,?,?,?,?,?)", rows)
        self.last_update = now
        self.db.set_meta("wifi_last_update", str(now))
        return stats

    def _open(self, mac, ap, band, link, rssi, now) -> None:
        sid = self.db.x("INSERT INTO wifi_sessions(mac, start, last_ts, ap, band, link, rssi_first, rssi_last, "
                        "rssi_min, samples) VALUES(?,?,?,?,?,?,?,?,?,1)",
                        [mac, now, now, ap, band, link, rssi, rssi, rssi])
        self.open[mac] = {"id": sid, "mac": mac, "start": now, "last_ts": now, "ap": ap, "band": band,
                          "rssi_min": rssi, "rssi_last": rssi, "samples": 1}

    def _touch(self, s: dict, rssi, now) -> None:
        s["last_ts"], s["samples"] = now, s["samples"] + 1
        if rssi is not None:
            s["rssi_last"] = rssi
            s["rssi_min"] = rssi if s["rssi_min"] is None else min(s["rssi_min"], rssi)
        self.db.x("UPDATE wifi_sessions SET last_ts=?, rssi_last=?, rssi_min=?, samples=? WHERE id=?",
                  [now, s["rssi_last"], s["rssi_min"], s["samples"], s["id"]])

    def _close(self, mac: str, end: int, reason: str) -> None:
        s = self.open.pop(mac, None)
        if s:
            self.db.x("UPDATE wifi_sessions SET end=?, end_reason=? WHERE id=?", [end, reason, s["id"]])


# ------------------------------------------------------------------ analyse
def issues(st: dict, per_day: float) -> list[dict]:
    """Diagnostic d'un appareil à partir de ses statistiques (fonction pure, testée)."""
    out = []
    if st["connected_s"] < MIN_CONNECTED_S:
        return [{"level": "info", "code": "no_data", "text": "Pas assez de relevés pour conclure."}]
    drops = st["drops"] * per_day
    rd = st.get("rssi_at_drop")
    if drops >= 8:
        if rd is not None and rd <= WEAK_RSSI:
            out.append({"level": "critical", "code": "coverage",
                        "text": f"Coupures à signal faible ({rd:.0f} dBm en moyenne juste avant) : problème de "
                                f"couverture. Rapprochez l'appareil ou ajoutez un point d'accès."})
        else:
            sig = f" malgré un bon signal ({rd:.0f} dBm)" if rd is not None else ""
            out.append({"level": "warning", "code": "settings",
                        "text": f"Coupures{sig} : ce n'est pas la portée. Pistes : canal DFS ou 160 MHz, "
                                f"bascules entre bandes, adresse MAC privée, économie d'énergie Wi-Fi."})
    if st["roams"] * per_day >= 20:
        out.append({"level": "warning", "code": "pingpong",
                    "text": "Ping-pong entre points d'accès : l'appareil bascule sans cesse entre la box et un "
                            "répéteur, ce qui coupe la connexion à chaque passage."})
    if st["bands"] * per_day >= 20:
        out.append({"level": "warning", "code": "bandflip",
                    "text": "Bascules fréquentes entre bandes (2,4 / 5 / 6 GHz) : séparer les noms de réseau "
                            "par bande aide souvent."})
    avg = st.get("rssi_avg")
    if avg is not None and avg <= WEAK_RSSI:
        out.append({"level": "warning", "code": "weak",
                    "text": f"Signal faible en moyenne ({avg:.0f} dBm)."})
    ping = st.get("ping_up")
    if ping is not None and ping < 0.9 and st["connected_s"] >= 3600:
        out.append({"level": "info", "code": "unreachable",
                    "text": f"Associé au Wi-Fi mais injoignable {100 * (1 - ping):.0f} % du temps : veille ou "
                            f"économie d'énergie de l'appareil (pas une panne du réseau)."})
    if not out:
        out.append({"level": "ok", "code": "ok", "text": "Connexion stable."})
    return out


def report(db: DB, start: int, end: int, names: dict[str, str] | None = None, now: int | None = None) -> dict:
    """Statistiques Wi-Fi par appareil sur [start, end]."""
    names = names or {}
    first = db.q1("SELECT MIN(ts) AS t FROM wifi_samples")
    span = max(end - max(start, (first or {}).get("t") or end), 0)
    per_day = 86400 / max(span, MIN_SPAN_S)
    sessions = db.q("SELECT * FROM wifi_sessions WHERE start <= ? AND COALESCE(end, last_ts) >= ? ORDER BY start",
                    [end, start])
    by_mac: dict[str, list[dict]] = {}
    for s in sessions:
        by_mac.setdefault(s["mac"], []).append(s)
    devices = {r["mac"]: r for r in db.q("SELECT id, mac, alias, hostname, random_mac, dev_type FROM devices "
                                          "WHERE kind='lan'")}
    out = []
    for mac, ss in by_mac.items():
        dev = devices.get(mac) or {}
        connected = sum(max(0, min(s["end"] or s["last_ts"], end) - max(s["start"], start)) for s in ss)
        drops = [s for s in ss if s["end_reason"] == "drop" and start <= (s["end"] or 0) <= end]
        rd = [s["rssi_last"] for s in drops if s["rssi_last"] is not None]
        samp = db.q1("SELECT AVG(rssi) AS a, MIN(rssi) AS m, COUNT(*) AS n FROM wifi_samples "
                     "WHERE mac=? AND ts BETWEEN ? AND ? AND rssi IS NOT NULL", [mac, start, end]) or {}
        share = {"ap": {}, "band": {}}
        for r in db.q("SELECT ap, band, COUNT(*) AS n FROM wifi_samples WHERE mac=? AND ts BETWEEN ? AND ? "
                      "GROUP BY ap, band", [mac, start, end]):
            share["ap"][r["ap"]] = share["ap"].get(r["ap"], 0) + r["n"]
            share["band"][r["band"] or "?"] = share["band"].get(r["band"] or "?", 0) + r["n"]
        ping_up = None
        if dev.get("id") is not None:
            up = n = 0
            for s in ss[-300:]:
                a, b = max(s["start"], start), min(s["end"] or s["last_ts"], end)
                if b <= a:
                    continue
                r = db.q1("SELECT SUM(up) AS u, COUNT(*) AS n FROM samples WHERE device_id=? AND ts BETWEEN ? AND ?",
                          [dev["id"], a, b])
                up, n = up + (r["u"] or 0), n + (r["n"] or 0)
            ping_up = up / n if n >= 10 else None
        last = ss[-1]
        st = {
            "mac": mac, "device_id": dev.get("id"),
            "name": dev.get("alias") or names.get(mac) or dev.get("hostname") or mac,
            "random_mac": bool(dev.get("random_mac")), "dev_type": dev.get("dev_type"),
            "online": last["end"] is None, "ap": last["ap"], "band": last["band"], "link": last["link"],
            "sessions": len(ss), "drops": len(drops),
            "roams": sum(1 for s in ss if s["end_reason"] == "roam"),
            "bands": sum(1 for s in ss if s["end_reason"] == "band"),
            "connected_s": connected, "longest_s": max((min(s["end"] or s["last_ts"], end) - max(s["start"], start)
                                                        for s in ss), default=0),
            "rssi_avg": round(samp["a"], 1) if samp.get("a") is not None else None,
            "rssi_min": samp.get("m"), "rssi_at_drop": round(sum(rd) / len(rd), 1) if rd else None,
            "ping_up": None if ping_up is None else round(ping_up, 3), "share": share,
        }
        st["issues"] = issues(st, per_day)
        st["worst"] = max((i["level"] for i in st["issues"]), key=["ok", "info", "warning", "critical"].index)
        out.append(st)
    out.sort(key=lambda s: (-["ok", "info", "warning", "critical"].index(s["worst"]), -s["drops"]))
    return {"devices": out, "start": start, "end": end, "span": span, "now": now}


def device_detail(db: DB, mac: str, start: int, end: int, step: int) -> dict:
    """Courbe de signal (moyenne par tranche, avec le point d'accès dominant) + dernières sessions."""
    rows = db.q("SELECT ts, ap, band, rssi, rate FROM wifi_samples WHERE mac=? AND ts BETWEEN ? AND ? ORDER BY ts",
                [mac, start, end])
    buckets: dict[int, list] = {}
    for r in rows:
        buckets.setdefault(r["ts"] // step * step, []).append(r)
    series = []
    for t, rs in sorted(buckets.items()):
        vals = [r["rssi"] for r in rs if r["rssi"] is not None]
        aps = [r["ap"] for r in rs]
        series.append({"ts": t, "rssi": round(sum(vals) / len(vals)) if vals else None,
                       "ap": max(set(aps), key=aps.count), "band": rs[-1]["band"]})
    sessions = db.q("SELECT start, end, last_ts, ap, band, link, rssi_first, rssi_last, rssi_min, end_reason "
                    "FROM wifi_sessions WHERE mac=? AND start <= ? AND COALESCE(end, last_ts) >= ? "
                    "ORDER BY start DESC LIMIT 100", [mac, end, start])
    return {"series": series, "sessions": sessions}


def purge(db: DB, sample_days: int, session_days: int, now: int) -> None:
    db.x("DELETE FROM wifi_samples WHERE ts < ?", [now - sample_days * 86400])
    db.x("DELETE FROM wifi_sessions WHERE end IS NOT NULL AND end < ?", [now - session_days * 86400])


def radios_changed(old_json: str | None, cfg: dict | None) -> list[tuple[str, int | None, int | None]]:
    """Canaux modifiés depuis le relevé précédent : [(bande, ancien, nouveau)]."""
    if not cfg or not old_json:
        return []
    try:
        old = json.loads(old_json)
    except ValueError:
        return []
    return [(b, old[b], v["channel"]) for b, v in cfg["bands"].items()
            if b in old and old[b] and v["channel"] and old[b] != v["channel"]]
