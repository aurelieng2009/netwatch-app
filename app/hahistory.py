"""Import de l'historique de disponibilité Zigbee depuis l'API REST de Home Assistant.

Zigbee2MQTT ne conserve aucun historique : pour diagnostiquer les dernières 24 h sans attendre,
on relit l'historique des entités que Home Assistant a créées pour chaque appareil. Quand
l'appareil est hors ligne, toutes ses entités passent à `unavailable` : l'appareil est donc
considéré hors ligne lorsque toutes les entités retenues le sont. Les capteurs `*_linkquality`
et `*_battery`, s'ils existent, alimentent aussi les courbes de qualité de lien.

Le jeton n'est envoyé qu'à une adresse locale (IP privée ou nom local), jamais à Internet.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import ssl
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import z2mnames
from .db import DB

log = logging.getLogger("netwatch.ha")

DOMAINS = ("light", "switch", "cover", "climate", "lock", "fan", "binary_sensor", "sensor")
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".home.arpa", ".localdomain")
MAX_ENTITIES_PER_DEVICE = 4
CHUNK = 25
SAMPLE_EVERY = 300


class HAError(Exception):
    """Erreur lisible côté interface."""


def url_allowed(url: str) -> bool:
    """Le jeton ne part que vers une adresse du réseau local."""
    try:
        p = urllib.parse.urlparse((url or "").strip())
        host = (p.hostname or "").lower()
    except ValueError:
        return False
    if p.scheme not in ("http", "https") or not host or p.username or p.password:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_link_local or ip.is_loopback
    except ValueError:
        return "." not in host or host.endswith(LOCAL_SUFFIXES)


def slug(text: str) -> str:
    """Équivalent simplifié du `slugify` de Home Assistant (accents retirés, `_` comme séparateur)."""
    t = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", "_", t).strip("_")


def _iso(ts: float) -> str:
    return urllib.parse.quote(datetime.fromtimestamp(ts, timezone.utc).isoformat(), safe=":")


def _parse_ts(s: str) -> float:
    return datetime.fromisoformat(s).timestamp()


def _context(verify: bool) -> ssl.SSLContext | None:
    if verify:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(base: str, token: str, path: str, payload: dict | None = None, timeout: float = 60.0,
             verify: bool = True) -> bytes:
    req = urllib.request.Request(base.rstrip("/") + "/api/" + path, headers={"Authorization": f"Bearer {token}"})
    if payload is not None:
        req.data = json.dumps(payload).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_context(verify)) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise HAError("jeton refusé par Home Assistant") from e
        raise HAError(f"Home Assistant a répondu HTTP {e.code}") from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            raise HAError("certificat de Home Assistant refusé (auto-signé ?) : cochez « Ignorer le certificat » puis réessayez") from e
        raise HAError(f"Home Assistant injoignable ({e.reason})") from e
    except (OSError, TimeoutError) as e:
        raise HAError(f"Home Assistant injoignable ({getattr(e, 'reason', e)})") from e


def _get(base: str, token: str, path: str, timeout: float = 60.0, verify: bool = True):
    try:
        return json.loads(_request(base, token, path, None, timeout, verify))
    except ValueError as e:
        raise HAError("réponse illisible de Home Assistant (URL incorrecte ?)") from e


# noms et rattachement exact : pour chaque entité MQTT, son appareil HA, le nom choisi par l'utilisateur
# (à défaut celui de l'intégration) et ses identifiants, qui contiennent l'adresse IEEE de l'appareil Zigbee
#   dev[d] : n = nom, i = identifiants, a = pièce, m = modèle, v = fabricant
#   ex[e]  : c = classe de l'entité, f = son nom, a = noms des automatisations qui l'utilisent
DEVICES_TEMPLATE = """
{% set ns = namespace(ent={}, dev={}, ex={}) %}
{% for e in integration_entities('mqtt') %}
{% set d = device_id(e) %}
{% if d %}
{% set ns.ent = ns.ent | combine({e: d}) %}
{% set au = namespace(l=[]) %}
{% for a in automations_with_entity(e) %}{% set au.l = au.l + [state_attr(a, 'friendly_name')] %}{% endfor %}
{% set ns.ex = ns.ex | combine({e: {'c': state_attr(e, 'device_class'), 'f': state_attr(e, 'friendly_name'), 'a': au.l}}) %}
{% if d not in ns.dev %}
{% set ns.dev = ns.dev | combine({d: {'n': device_attr(d, 'name_by_user') or device_attr(d, 'name'),
                                      'i': device_attr(d, 'identifiers') | map('join', ' ') | list,
                                      'a': area_name(d), 'm': device_attr(d, 'model'),
                                      'v': device_attr(d, 'manufacturer')}}) %}
{% endif %}
{% endif %}
{% endfor %}
{{ {'ent': ns.ent, 'dev': ns.dev, 'ex': ns.ex} | to_json }}
"""
_IEEE = re.compile(r"0x[0-9a-fA-F]{16}")


def _template(base: str, token: str, template: str, verify: bool = True) -> str:
    return _request(base, token, "template", {"template": template}, 120, verify).decode("utf-8", "replace")


def device_info(base: str, token: str, verify: bool = True) -> dict:
    """{'names': {ieee: nom HA}, 'entities': {entity_id: ieee}, 'context': {ieee: {area, vendor, model, ents}}}
    d'après le registre d'appareils de HA (`context` alimente la suggestion de noms de z2mnames.py)."""
    raw = _template(base, token, DEVICES_TEMPLATE, verify).strip()
    try:
        data = json.loads(raw)
        ent, dev = data["ent"], data["dev"]
        ex = data.get("ex") or {}
    except (ValueError, KeyError, TypeError) as e:
        raise HAError("réponse inattendue au modèle de noms d'appareils") from e
    by_device: dict[str, str] = {}
    names: dict[str, str] = {}
    context: dict[str, dict] = {}
    for did, info in dev.items():
        m = next((_IEEE.search(i) for i in info.get("i") or [] if _IEEE.search(i)), None)
        if m:
            ieee = m.group(0).lower()
            by_device[did] = ieee
            context[ieee] = {"area": info.get("a"), "vendor": info.get("v"), "model": info.get("m"), "ents": []}
            if info.get("n"):
                names[ieee] = str(info["n"])
    entities = {e: by_device[d] for e, d in ent.items() if d in by_device}
    for e, ieee in entities.items():
        x = ex.get(e) or {}
        context[ieee]["ents"].append({"id": e, "class": x.get("c"), "name": x.get("f"),
                                      "automations": [a for a in x.get("a") or [] if a]})
    return {"names": names, "entities": entities, "context": context}


# ------------------------------------------------------------------ association entités ↔ appareils
def match_entities(devices: list[dict], states: list[dict], exact: dict[str, str] | None = None) -> dict[str, list[str]]:
    """{ieee: [entity_id…]}. `exact` (entity_id → ieee, issu du registre d'appareils de HA) prime ; sinon
    l'entité appartient à l'appareil dont le nom (ou l'adresse IEEE) est le plus long préfixe de son
    identifiant. Couvre les deux nommages observés dans HA : `sensor.salon_lampe_battery` et
    `sensor.0x70ac08fffefceb80_linkquality`."""
    exact = exact or {}
    known = {d["ieee"] for d in devices if d["type"] != "Coordinator"}
    keys: dict[str, str] = {}
    for d in devices:
        if d["type"] == "Coordinator":
            continue
        keys[d["ieee"].lower()] = d["ieee"]
        s = slug(d["name"])
        if s:
            keys.setdefault(s, d["ieee"])
    out: dict[str, list[str]] = {}
    for st in states:
        eid = st.get("entity_id", "")
        domain, _, obj = eid.partition(".")
        if domain not in DOMAINS:
            continue
        if exact.get(eid) in known:
            out.setdefault(exact[eid], []).append(eid)
            continue
        best = None
        for k, ieee in keys.items():
            if (obj == k or obj.startswith(k + "_")) and (best is None or len(k) > len(best[0])):
                best = (k, ieee)
        if best:
            out.setdefault(best[1], []).append(eid)
    return out


def _is_metric(eid: str) -> bool:
    return eid.endswith(("_linkquality", "_battery"))


def pick_entities(entity_ids: list[str]) -> list[str]:
    """Entités qui décident de la disponibilité : les principales d'abord, les métriques en dernier recours."""
    rank = {d: i for i, d in enumerate(DOMAINS)}
    main = sorted((e for e in entity_ids if not _is_metric(e)), key=lambda e: (rank[e.split(".")[0]], e))
    return (main or sorted(entity_ids))[:MAX_ENTITIES_PER_DEVICE]


# ------------------------------------------------------------------ reconstruction de la chronologie
def availability_timeline(histories: dict[str, list[tuple[float, str]]]) -> list[tuple[float, bool]]:
    """Fusionne l'historique de plusieurs entités : [(ts, en_ligne)] aux seuls changements.
    En ligne dès qu'une entité connue ne l'est pas `unavailable`."""
    events = sorted((ts, eid, st == "unavailable") for eid, h in histories.items() for ts, st in h)
    cur: dict[str, bool] = {}
    out: list[tuple[float, bool]] = []
    for ts, eid, unavailable in events:
        cur[eid] = unavailable
        online = not all(cur.values())
        if not out or out[-1][1] != online:
            out.append((ts, online))
    return out


def _history(base: str, token: str, eids: list[str], start: float, end: float,
             verify: bool = True) -> dict[str, list[tuple[float, str]]]:
    out: dict[str, list[tuple[float, str]]] = {}
    for i in range(0, len(eids), CHUNK):
        chunk = eids[i:i + CHUNK]
        path = (f"history/period/{_iso(start)}?filter_entity_id={','.join(chunk)}"
                f"&end_time={_iso(end)}&minimal_response&no_attributes")
        data = _get(base, token, path, timeout=120, verify=verify)
        for series in data if isinstance(data, list) else []:
            if not series:
                continue
            eid = series[0].get("entity_id")
            if not eid:
                continue
            h = []
            for s in series:
                try:
                    h.append((max(_parse_ts(s.get("last_changed") or s.get("last_updated")), start), str(s.get("state"))))
                except (TypeError, ValueError):
                    continue
            out[eid] = h
    return out


# ------------------------------------------------------------------ import
def import_history(db: DB, base_url: str, token: str, hours: int, verify_tls: bool = True) -> dict:
    if not base_url:
        raise HAError("URL de Home Assistant non renseignée")
    if not url_allowed(base_url):
        raise HAError("URL refusée : le jeton ne part que vers une adresse locale (IP privée ou nom .local)")
    hours = max(1, min(int(hours), 168))
    now = time.time()
    start = now - hours * 3600
    devices = db.q("SELECT ieee, name, type FROM z2m_devices WHERE present=1 AND disabled=0")
    if not devices:
        raise HAError("aucun appareil connu : attendez que Zigbee2MQTT ait publié sa liste (bridge/devices)")
    states = _get(base_url, token, "states", verify=verify_tls)
    if not isinstance(states, list):
        raise HAError("réponse inattendue de Home Assistant")
    warning = None
    try:
        info = device_info(base_url, token, verify_tls)
    except HAError as e:          # noms indisponibles : l'import continue avec l'association par nom
        info, warning = {"names": {}, "entities": {}, "context": {}}, f"Noms Home Assistant non récupérés ({e})."
    matched = match_entities(devices, states, info["entities"])
    named = {i: n for i, n in info["names"].items() if not z2mnames.IEEE_ONLY.match(n)}
    if info["names"]:
        db.x("UPDATE z2m_devices SET ha_name=NULL")
        db.xmany("UPDATE z2m_devices SET ha_name=? WHERE ieee=?", [(n, i) for i, n in named.items()])
    guesses: dict[str, dict] = {}
    if info["context"]:           # suggestions pour les appareils qui n'ont toujours que leur adresse IEEE
        guesses = z2mnames.guess(db.q("SELECT ieee, name, ha_name, vendor, model FROM z2m_devices "
                                      "WHERE present=1 AND disabled=0 AND type != 'Coordinator'"), info["context"])
        db.x("UPDATE z2m_devices SET ha_guess=NULL")
        db.xmany("UPDATE z2m_devices SET ha_guess=? WHERE ieee=?",
                 [(json.dumps(g, ensure_ascii=False), i) for i, g in guesses.items()])
    entity_ids = sorted({e for v in matched.values() for e in v})

    # l'import s'arrête là où l'écoute MQTT prend le relais
    first_mqtt = db.q1("SELECT MIN(ts) AS t FROM z2m_avail WHERE ieee != 'bridge' AND src IN ('mqtt','init') AND ts >= ?",
                       [int(start)])
    cutoff = first_mqtt["t"] if first_mqtt and first_mqtt["t"] else now

    hist = _history(base_url, token, entity_ids, start, cutoff, verify_tls) if entity_ids else {}
    db.x("DELETE FROM z2m_avail WHERE src='ha' AND ts >= ?", [int(start)])

    rows, samples, drops, with_data = [], [], 0, 0
    for ieee, eids in matched.items():
        chosen = pick_entities(eids)
        tl = availability_timeline({e: hist[e] for e in chosen if e in hist})
        if tl:
            with_data += 1
            rows += [(int(ts), ieee, int(on), "ha") for ts, on in tl if ts <= cutoff]
            drops += sum(1 for (_, prev), (ts, on) in zip(tl, tl[1:]) if prev and not on and ts <= cutoff)
        lqi_e = next((e for e in eids if e.endswith("_linkquality") and e in hist), None)
        bat_e = next((e for e in eids if e.endswith("_battery") and e in hist), None)
        first = db.q1("SELECT MIN(ts) AS t FROM z2m_samples WHERE ieee=?", [ieee])
        limit = first["t"] if first and first["t"] else cutoff
        by_ts: dict[int, list] = {}
        for col, eid in ((0, lqi_e), (1, bat_e)):
            last = 0
            for ts, st in hist.get(eid, []):
                try:
                    v = int(float(st))
                except ValueError:
                    continue
                if ts < limit and ts - last >= SAMPLE_EVERY:
                    by_ts.setdefault(int(ts), [None, None])[col] = v
                    last = ts
        samples += [(ts, ieee, v[0], v[1]) for ts, v in by_ts.items()]
    db.xmany("INSERT INTO z2m_avail(ts, ieee, online, src) VALUES(?,?,?,?)", rows)
    db.xmany("INSERT INTO z2m_samples(ts, ieee, lqi, battery) VALUES(?,?,?,?)", samples)
    real = [d for d in devices if d["type"] != "Coordinator"]
    return {
        "devices": len(real), "matched": len(matched), "with_history": with_data,
        "unmatched": sorted(d["name"] for d in real if d["ieee"] not in matched)[:15],
        "named": sum(1 for d in real if d["ieee"] in named), "guessed": len(guesses), "warning": warning,
        "drops": drops, "transitions": len(rows), "samples": len(samples),
        "start": int(start), "end": int(cutoff),
    }
