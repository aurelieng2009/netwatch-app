"""Suggestion de noms pour les appareils Zigbee qui n'en ont pas (nom = adresse IEEE `0x70ac…`).

Déduction à partir de ce que Home Assistant sait de l'appareil : sa pièce, le type de ses entités
(ouverture, mouvement, température, lumière…), les automatisations qui l'utilisent et son modèle.
C'est une heuristique : le résultat est toujours présenté comme une suggestion (avec ses indices et
un niveau de confiance) et ne remplace jamais un nom choisi par l'utilisateur.
"""
from __future__ import annotations

import re

IEEE_ONLY = re.compile(r"^0x[0-9a-f]{16}$", re.I)

BINARY = {
    "door": "ouverture", "window": "ouverture", "opening": "ouverture", "garage_door": "porte de garage",
    "motion": "mouvement", "occupancy": "présence", "presence": "présence", "moisture": "fuite d'eau",
    "smoke": "fumée", "gas": "gaz", "carbon_monoxide": "CO", "vibration": "vibration", "lock": "serrure",
}
DOMAIN = {"light": "lumière", "cover": "volet", "climate": "thermostat", "lock": "serrure", "fan": "ventilateur",
          "switch": "prise"}
SENSOR = {"temperature": "température", "humidity": "humidité", "illuminance": "luminosité", "pressure": "pression",
          "co2": "CO₂", "pm25": "qualité de l'air", "voc": "qualité de l'air"}
NOISE = ("_linkquality", "_battery", "_voltage", "_identify", "_update", "_last_seen", "_device_temperature")


def needs_name(ha_name: str | None, z2m_name: str) -> bool:
    """Vrai quand le meilleur nom connu n'est qu'une adresse IEEE."""
    return bool(IEEE_ONLY.match(ha_name or z2m_name))


def _kind(ents: list[dict]) -> str | None:
    """Type de l'appareil d'après ses entités : spécifique (ouverture, mouvement) > domaine (lumière, volet)
    > mesures (température…) > télécommande."""
    kinds: dict[int, list[str]] = {0: [], 1: [], 2: [], 3: []}
    for e in ents:
        eid = e["id"]
        if eid.endswith(NOISE):
            continue
        domain = eid.split(".")[0]
        cls = e.get("class")
        if domain == "binary_sensor" and cls in BINARY:
            kinds[0].append(BINARY[cls])
        elif domain in DOMAIN and domain != "switch":
            kinds[1].append(DOMAIN[domain])
        elif domain == "sensor" and cls in SENSOR:
            kinds[2].append(SENSOR[cls])
        elif domain in ("event", "button") or eid.endswith("_action"):
            kinds[3].append("télécommande")
        elif domain == "switch":
            kinds[1].append(DOMAIN["switch"])
    for level in (0, 1, 2, 3):
        uniq = list(dict.fromkeys(kinds[level]))
        if uniq:
            return "/".join(uniq[:2])
    return None


def guess(devices: list[dict], context: dict[str, dict]) -> dict[str, dict]:
    """{ieee: {name, confidence, evidence}} pour les appareils sans vrai nom.

    devices : [{ieee, name, ha_name, vendor, model}] ; context : {ieee: {area, vendor, model, ents:[{id, class, name,
    automations}]}} tel que rendu par hahistory.device_info."""
    out: dict[str, dict] = {}
    used: dict[str, int] = {}
    for d in sorted(devices, key=lambda d: d["ieee"]):
        if not needs_name(d.get("ha_name"), d["name"]):
            continue
        c = context.get(d["ieee"]) or {}
        area, ents = c.get("area"), c.get("ents") or []
        kind = _kind(ents)
        model = " ".join(x for x in (c.get("vendor") or d.get("vendor"), c.get("model") or d.get("model")) if x)
        autos = list(dict.fromkeys(a for e in ents for a in e.get("automations") or [] if a))
        if area and kind:
            name, conf = f"{area} – {kind}", "haute"
        elif kind and autos:
            name, conf = f"{kind.capitalize()} – {autos[0][:40]}", "moyenne"
        elif area and model:
            name, conf = f"{area} – {model}", "moyenne"
        elif kind:
            name, conf = kind.capitalize(), "faible"
        elif model:
            name, conf = model, "faible"
        else:
            continue
        used[name] = used.get(name, 0) + 1          # deux appareils du même type dans la même pièce
        if used[name] > 1:
            name = f"{name} {used[name]}"
        evidence = []
        if area:
            evidence.append(f"pièce : {area}")
        shown = [e["name"] for e in ents if e.get("name") and not e["id"].endswith(NOISE)][:3]
        if shown:
            evidence.append("entités : " + ", ".join(shown))
        if autos:
            evidence.append("automatisations : " + ", ".join(a[:40] for a in autos[:3]))
        if model:
            evidence.append(f"modèle : {model}")
        out[d["ieee"]] = {"name": name, "confidence": conf, "evidence": evidence}
    return out
