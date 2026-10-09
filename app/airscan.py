"""Environnement radio : réseaux Wi-Fi voisins, occupation des canaux et recoupement avec Zigbee.

Le serveur n'a pas de carte Wi-Fi : un petit agent tourne sur une machine qui en a une (PC Windows,
`tools/netwatch-wifi-agent.ps1`) et envoie la sortie brute de `netsh wlan show networks mode=bssid`
(et `show interfaces`). On l'analyse ici : canaux 2,4 GHz saturés, meilleur canal Wi-Fi, et surtout
quel canal Zigbee évite le mieux les points d'accès réellement présents (au lieu de supposer que
tout le monde est sur les canaux 1, 6 et 11).
"""
from __future__ import annotations

import json
import re
import secrets
import time
import unicodedata

META_LAST = "air:last"
META_TOKEN = "air_token"
STALE_S = 1800
MIN_SIGNAL = 15           # % : en dessous, le point d'accès ne gêne pas vraiment
BUSY_PCT = 30             # occupation du canal jugée élevée (%)

_MAC = r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}"


def _fold(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn").lower().strip()


def _int(s):
    m = re.search(r"-?\d+", s or "")
    return int(m.group()) if m else None


def _band(s: str, channel: int | None) -> str | None:
    t = (s or "").replace(",", ".")
    for b in ("2.4", "5", "6"):
        if re.search(rf"\b{re.escape(b)}\s*ghz", t, re.I):
            return b
    if channel is not None and channel <= 14:
        return "2.4"
    return None


def parse_networks(text: str) -> list[dict]:
    """Sortie de `netsh wlan show networks mode=bssid` (FR ou EN) → liste de points d'accès."""
    aps: list[dict] = []
    ssid = ""
    cur: dict | None = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        m = re.match(r"^\s*SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            ssid, cur = m.group(1).strip(), None
            continue
        m = re.match(rf"^\s*BSSID\s+\d+\s*:\s*({_MAC})", line, re.I)
        if m:
            cur = {"ssid": ssid, "bssid": m.group(1).lower(), "signal": None, "radio": None,
                   "band_raw": "", "channel": None, "util": None, "stations": None}
            aps.append(cur)
            continue
        if cur is None or ":" not in line:
            continue
        key, _, val = line.partition(":")
        k = _fold(key)
        if k.startswith("bssid") or k.startswith("point d'acces"):
            continue                     # liste des points d'accès colocalisés
        if k == "signal":
            cur["signal"] = _int(val)
        elif k in ("type de radio", "radio type"):
            cur["radio"] = val.strip()
        elif k in ("bande", "band"):
            cur["band_raw"] = val.strip()
        elif k in ("canal", "channel"):
            cur["channel"] = _int(val)
        elif k.startswith("utilisation du canal") or k.startswith("channel utilization"):
            m2 = re.search(r"\((\d+)\s*%\)", val)
            cur["util"] = int(m2.group(1)) if m2 else (round(_int(val) / 2.55) if _int(val) is not None else None)
        elif k.startswith("stations conn") or k.startswith("connected stations"):
            cur["stations"] = _int(val)
    out = []
    for a in aps:
        a["band"] = _band(a.pop("band_raw"), a["channel"])
        if a["channel"] is not None and a["band"]:
            out.append(a)
    return out


def parse_connected(text: str) -> dict | None:
    """Sortie de `netsh wlan show interfaces` → point d'accès auquel le PC est associé."""
    d: dict = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        k, v = _fold(key), val.strip()
        if k == "ssid":
            d["ssid"] = v
        elif k == "bssid":
            d["bssid"] = v.lower()
        elif k in ("canal", "channel"):
            d["channel"] = _int(v)
        elif k in ("bande", "band"):
            d["band"] = _band(v, d.get("channel"))
        elif k == "signal":
            d["signal"] = _int(v)
    return d if d.get("ssid") else None


# ------------------------------------------------------------------ analyse
def _weight(ap: dict) -> float:
    """Gêne d'un point d'accès : signal fort et canal occupé = plus gênant."""
    s = ap.get("signal") or 0
    if s < MIN_SIGNAL:
        return 0.0
    util = ap.get("util")
    return (s / 100) ** 2 * (0.5 + (util if util is not None else 20) / 100)


def _wifi24_mhz(ch: int) -> int:
    return 2484 if ch == 14 else 2407 + 5 * ch


def _zigbee_mhz(ch: int) -> int:
    return 2405 + 5 * (ch - 11)


def wifi24_scores(aps: list[dict]) -> list[dict]:
    """Charge par canal 2,4 GHz (1 à 13) : chevauchement des canaux voisins pondéré."""
    a24 = [a for a in aps if a["band"] == "2.4"]
    out = []
    for c in range(1, 14):
        score, who = 0.0, 0
        for a in a24:
            delta = abs(a["channel"] - c)
            if delta <= 4:
                score += _weight(a) * (1 - delta / 5)
                who += 1 if a["channel"] == c else 0
        out.append({"channel": c, "score": round(score, 2), "aps": who})
    return out


def zigbee_scores(aps: list[dict]) -> list[dict]:
    """Charge Wi-Fi qui recouvre chaque canal Zigbee (11 à 26) : Wi-Fi 20 MHz = ±11 MHz."""
    a24 = [a for a in aps if a["band"] == "2.4" and a["channel"] <= 13]
    out = []
    for z in range(11, 27):
        score, hits = 0.0, []
        for a in a24:
            gap = abs(_zigbee_mhz(z) - _wifi24_mhz(a["channel"]))
            if gap < 12:
                score += _weight(a) * (1 - gap / 12 * 0.5)
                hits.append(a["channel"])
        out.append({"channel": z, "score": round(score, 2), "wifi_channels": sorted(set(hits))})
    return out


def wifi5_summary(aps: list[dict]) -> list[dict]:
    by: dict[int, list[dict]] = {}
    for a in aps:
        if a["band"] == "5":
            by.setdefault(a["channel"], []).append(a)
    return [{"channel": c, "aps": len(v), "signal_max": max((x.get("signal") or 0) for x in v),
             "util_max": max((x.get("util") or 0) for x in v)} for c, v in sorted(by.items())]


def findings(aps: list[dict], w24: list[dict], zb: list[dict], wifi_ch: int | None,
             zb_ch: int | None) -> list[dict]:
    out: list[dict] = []
    a24 = [a for a in aps if a["band"] == "2.4" and (a.get("signal") or 0) >= MIN_SIGNAL]
    if a24:
        chans = sorted({a["channel"] for a in a24})
        out.append({"level": "info", "title": f"{len(a24)} points d'accès 2,4 GHz audibles sur les canaux {', '.join(map(str, chans))}",
                    "detail": "Le 2,4 GHz n'a que 3 canaux qui ne se chevauchent pas (1, 6, 11). Des points d'accès sur "
                              "d'autres canaux (4, 8…) empiètent sur plusieurs canaux à la fois."})
    off = sorted({a["channel"] for a in a24 if a["channel"] not in (1, 6, 11) and (a.get("signal") or 0) >= 40})
    if off:
        out.append({"level": "warning", "title": f"Canaux 2,4 GHz hors 1/6/11 utilisés par des voisins forts : {', '.join(map(str, off))}",
                    "detail": "Un point d'accès sur un canal intermédiaire brouille deux ou trois canaux voisins. "
                              "Si c'est un de vos équipements (répéteur, mesh), fixez-le sur 1, 6 ou 11."})
    busy = [a for a in a24 if (a.get("util") or 0) >= BUSY_PCT and (a.get("signal") or 0) >= 40]
    if busy:
        seen = {(a["ssid"] or "(masqué)", a["channel"], a["util"]) for a in busy}
        txt = ", ".join(f"{s} canal {c} ({u} % occupé)" for s, c, u in sorted(seen, key=lambda x: -x[2])[:4])
        out.append({"level": "warning", "title": "Canaux 2,4 GHz très occupés",
                    "detail": f"{txt}. Au-delà de ~30 % d'occupation, chaque appareil attend son tour pour parler : "
                              "latence et coupures, surtout pour les objets connectés."})
    if wifi_ch and w24:
        cur = next((x for x in w24 if x["channel"] == wifi_ch), None)
        cand = [x for x in w24 if x["channel"] in (1, 6, 11)]
        best = min(cand, key=lambda x: x["score"]) if cand else None
        if cur and best and best["channel"] != wifi_ch and best["score"] < cur["score"] * 0.7:
            out.append({"level": "warning", "title": f"La box est sur le canal 2,4 GHz {wifi_ch} ; le canal {best['channel']} est nettement plus libre",
                        "detail": f"Charge estimée : canal {wifi_ch} = {cur['score']}, canal {best['channel']} = {best['score']}. "
                                  "Changez le canal de la box (ou testez-le), puis relancez un scan."})
    if zb:
        best = min(zb, key=lambda x: (x["score"], -x["channel"]))
        cur = next((x for x in zb if x["channel"] == zb_ch), None) if zb_ch else None
        if cur and best["channel"] != zb_ch and best["score"] < cur["score"] * 0.6 and cur["score"] > 0.15:
            ch = f" (Wi-Fi {', '.join(map(str, cur['wifi_channels']))})" if cur["wifi_channels"] else ""
            out.append({"level": "warning", "title": f"Zigbee sur le canal {zb_ch} : recouvert par du Wi-Fi{ch}",
                        "detail": f"Le canal Zigbee {best['channel']} est le moins gêné par le Wi-Fi ambiant "
                                  f"(charge {best['score']} contre {cur['score']}). Changer de canal Zigbee demande de "
                                  "réappairer ou au moins de laisser les appareils suivre le coordinateur : faites-le "
                                  "de préférence en dernier recours, après avoir libéré le canal Wi-Fi."})
        elif cur and cur["score"] <= 0.15:
            out.append({"level": "ok", "title": f"Zigbee sur le canal {zb_ch} : peu gêné par le Wi-Fi ambiant",
                        "detail": "Les points d'accès 2,4 GHz audibles ne recouvrent pas ce canal."})
        elif not zb_ch:
            out.append({"level": "info", "title": f"Meilleur canal Zigbee d'après le Wi-Fi ambiant : {best['channel']}",
                        "detail": "Activez le diagnostic Zigbee2MQTT pour comparer au canal actuel."})
    return out


def analyze(snap: dict | None, wifi_ch: int | None = None, zb_ch: int | None = None,
            now: float | None = None) -> dict:
    if not snap:
        return {"available": False}
    now = now or time.time()
    aps = snap.get("aps") or []
    w24, zb, w5 = wifi24_scores(aps), zigbee_scores(aps), wifi5_summary(aps)
    cur24 = [a for a in aps if a["band"] == "2.4"]
    return {
        "available": True, "ts": snap["ts"], "age": int(now - snap["ts"]), "stale": now - snap["ts"] > STALE_S,
        "host": snap.get("host"), "connected": snap.get("connected"),
        "wifi24": w24, "zigbee": zb, "wifi5": w5,
        "box_channel": wifi_ch, "zigbee_channel": zb_ch,
        "best_wifi24": min((x for x in w24 if x["channel"] in (1, 6, 11)), key=lambda x: x["score"])["channel"],
        "best_zigbee": min(zb, key=lambda x: (x["score"], -x["channel"]))["channel"],
        "aps": sorted(aps, key=lambda a: -(a.get("signal") or 0)),
        "counts": {"2.4": len(cur24), "5": sum(a["band"] == "5" for a in aps), "6": sum(a["band"] == "6" for a in aps)},
        "findings": findings(aps, w24, zb, wifi_ch, zb_ch),
    }


# ------------------------------------------------------------------ stockage / jeton
def ingest(db, scan_text: str, iface_text: str = "", host: str = "") -> dict:
    aps = parse_networks(scan_text)
    if not aps:
        raise ValueError("aucun point d'accès reconnu dans la sortie fournie")
    snap = {"ts": int(time.time()), "host": (host or "")[:64], "aps": aps,
            "connected": parse_connected(iface_text)}
    db.set_meta(META_LAST, json.dumps(snap))
    return snap


def last(db) -> dict | None:
    raw = db.get_meta(META_LAST)
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


def token(db, regenerate: bool = False) -> str:
    t = db.get_meta(META_TOKEN)
    if not t or regenerate:
        t = secrets.token_urlsafe(24)
        db.set_meta(META_TOKEN, t)
    return t


def token_ok(db, presented: str | None) -> bool:
    t = db.get_meta(META_TOKEN)
    return bool(t and presented and secrets.compare_digest(t.encode(), presented.encode()))
