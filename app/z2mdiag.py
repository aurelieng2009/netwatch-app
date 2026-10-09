"""Diagnostic d'un réseau Zigbee2MQTT sur une période, à partir des données collectées par z2m.py.

Fonction pure : `build_report` lit la base et renvoie un dictionnaire (constats, appareils,
coupures simultanées, chronologie). Aucune écriture, aucun accès réseau.
"""
from __future__ import annotations

import json
import statistics

from .db import DB

STRIP_CELLS = 96
CLUSTER_GAP = 90            # s : deux chutes séparées de moins que ça appartiennent à la même coupure
CLUSTER_SPAN = 300          # s : durée maximale d'une coupure groupée
FLAP_WARN, FLAP_CRIT = 3, 8          # déconnexions, et au moins autant par 24 h
LQI_WEAK = 50               # 0-255 ; sous ce seuil, le lien est fragile
BATTERY_LOW = 15
CLEAR_CHANNELS = (15, 20, 25, 26)    # canaux Zigbee qui évitent les Wi-Fi 1, 6 et 11
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2, "good": 3}


def _dur(s: float) -> str:
    s = int(s)
    if s < 90:
        return f"{s} s"
    if s < 5400:
        return f"{round(s / 60)} min"
    return f"{s // 3600} h {round(s % 3600 / 60):02d}"


# ------------------------------------------------------------------ chronologie d'un appareil
def segments(before: dict | None, rows: list[dict], start: int, end: int) -> tuple[list[tuple], list[int]]:
    """([(début, fin, en_ligne)], [instants de déconnexion]) sur [start, end].
    `before` = dernier état connu avant la période (valable dès `start`)."""
    pts = [(start, bool(before["online"]))] if before else []
    pts += [(r["ts"], bool(r["online"])) for r in rows if start <= r["ts"] <= end]
    segs: list[tuple] = []
    drops: list[int] = []
    prev = None
    for ts, on in pts:
        if prev is not None and prev[1] == on:
            continue
        if prev is not None:
            segs.append((prev[0], ts, prev[1]))
            if prev[1] and not on:
                drops.append(ts)
        prev = (ts, on)
    if prev:
        segs.append((prev[0], end, prev[1]))
    return segs, drops


def _overlap(a0: float, a1: float, b0: float, b1: float) -> float:
    return max(0.0, min(a1, b1) - max(a0, b0))


def _strip(segs: list[tuple], start: int, end: int, cells: int = STRIP_CELLS) -> list[float | None]:
    """Part du temps passée en ligne dans chaque case (None = aucune donnée)."""
    step = (end - start) / cells
    out: list[float | None] = []
    for i in range(cells):
        c0, c1 = start + i * step, start + (i + 1) * step
        known = up = 0.0
        for s0, s1, on in segs:
            o = _overlap(s0, s1, c0, c1)
            known += o
            if on:
                up += o
        out.append(None if known < step * 0.05 else round(up / known, 3))
    return out


# ------------------------------------------------------------------ parenté (carte du réseau)
def parents_from_map(netmap: dict | None) -> tuple[dict, dict]:
    """(parent_of, lqi_to_parent) par adresse IEEE : relation 1 = la cible est l'enfant de la source."""
    parent_of: dict[str, str] = {}
    lqi: dict[str, int] = {}
    for lk in (netmap or {}).get("links") or []:
        if lk.get("rel") == 1:
            parent_of[lk["dst"]] = lk["src"]
            if lk.get("lqi") is not None:
                lqi[lk["dst"]] = lk["lqi"]
        elif lk.get("rel") == 0:
            parent_of.setdefault(lk["src"], lk["dst"])
    return parent_of, lqi


# ------------------------------------------------------------------ coupures simultanées
def find_clusters(drops: list[tuple[int, str]], total: int) -> list[list[tuple[int, str]]]:
    """Regroupe les déconnexions proches dans le temps ; ne garde que les groupes significatifs."""
    need = 3 if total >= 6 else 2
    groups: list[list[tuple[int, str]]] = []
    for ev in sorted(drops):
        g = groups[-1] if groups else None
        if g and ev[0] - g[-1][0] <= CLUSTER_GAP and ev[0] - g[0][0] <= CLUSTER_SPAN:
            g.append(ev)
        else:
            groups.append([ev])
    return [g for g in groups if len({i for _, i in g}) >= need]


def _channel_overlap(ch: int) -> str | None:
    """Canal(aux) Wi-Fi 2,4 GHz qui recouvrent ce canal Zigbee (11-26), ou None s'il est dégagé."""
    if ch in CLEAR_CHANNELS:
        return None
    zig = 2405 + 5 * (ch - 11)
    hit = [w for w in (1, 6, 11) if abs(zig - (2412 + 5 * (w - 1))) <= 11]
    return "/".join(map(str, hit)) if hit else None


# ------------------------------------------------------------------ rapport
def build_report(db: DB, start: int, end: int, info: dict | None = None, netmap: dict | None = None) -> dict:
    devs = db.q("SELECT * FROM z2m_devices WHERE present=1 AND disabled=0 AND type != 'Coordinator'")
    by_ieee = {d["ieee"]: d for d in devs}
    window = max(end - start, 1)

    before = {r["ieee"]: r for r in db.q(
        "SELECT a.* FROM z2m_avail a JOIN (SELECT ieee, MAX(ts) m FROM z2m_avail WHERE ts < ? GROUP BY ieee) p "
        "ON a.ieee=p.ieee AND a.ts=p.m", [start])}
    inwin: dict[str, list[dict]] = {}
    for r in db.q("SELECT * FROM z2m_avail WHERE ts >= ? AND ts <= ? ORDER BY ts", [start, end]):
        inwin.setdefault(r["ieee"], []).append(r)

    samples = {r["ieee"]: r for r in db.q(
        "SELECT ieee, AVG(lqi) AS avg, MIN(lqi) AS min, COUNT(lqi) AS n FROM z2m_samples "
        "WHERE ts >= ? AND ts <= ? AND lqi IS NOT NULL GROUP BY ieee", [start, end])}
    errs: dict[str, dict[str, int]] = {}
    for r in db.q("SELECT ieee, cat, COUNT(*) AS n FROM z2m_log WHERE kind='log' AND ts >= ? AND ts <= ? "
                  "GROUP BY ieee, cat", [start, end]):
        errs.setdefault(r["ieee"], {})[r["cat"]] = r["n"]
    ev_counts: dict[tuple, int] = {(r["ieee"], r["kind"]): r["n"] for r in db.q(
        "SELECT ieee, kind, COUNT(*) AS n FROM z2m_log WHERE kind != 'log' AND ts >= ? AND ts <= ? "
        "GROUP BY ieee, kind", [start, end])}
    parent_of, parent_lqi = parents_from_map(netmap)
    guesses = {d["ieee"]: json.loads(d["ha_guess"]) for d in devs if d["ha_guess"] and not d["ha_name"]}
    # nom Home Assistant s'il est connu ; à défaut une suggestion, marquée « ≈ » pour ne pas passer pour un vrai nom
    names = {d["ieee"]: d["ha_name"] or (f"≈ {guesses[d['ieee']]['name']}" if d["ieee"] in guesses else d["name"])
             for d in devs}
    for n in (netmap or {}).get("nodes") or []:
        names.setdefault(n["ieee"], n.get("name") or n["ieee"])

    # -- pont Zigbee2MQTT : les changements d'état pendant (ou juste après) son arrêt lui sont imputés
    bsegs, _ = segments(before.get("bridge"), inwin.get("bridge", []), start, end)
    bridge_out = [(s, e) for s, e, on in bsegs if not on]

    def bridge_related(ts: int) -> bool:
        return any(s - CLUSTER_GAP <= ts <= e + CLUSTER_SPAN for s, e in bridge_out)

    # -- appareils
    rows, all_drops, covered_since = [], [], None
    all_segs: dict[str, list[tuple]] = {}
    for d in devs:
        segs, drops = segments(before.get(d["ieee"]), inwin.get(d["ieee"], []), start, end)
        drops = [t for t in drops if not bridge_related(t)]
        all_segs[d["ieee"]] = segs
        covered = sum(e - s for s, e, _ in segs)
        offline = sum(e - s for s, e, on in segs if not on)
        if segs:
            covered_since = segs[0][0] if covered_since is None else min(covered_since, segs[0][0])
        all_drops += [(t, d["ieee"]) for t in drops]
        sm = samples.get(d["ieee"])
        er = errs.get(d["ieee"], {})
        rows.append({
            "ieee": d["ieee"], "name": names[d["ieee"]],
            "z2m_name": d["name"] if names[d["ieee"]] != d["name"] else None, "guess": guesses.get(d["ieee"]),
            "type": d["type"], "vendor": d["vendor"], "model": d["model"],
            "power": d["power"], "online": None if d["online"] is None else bool(d["online"]),
            "drops": len(drops), "offline_s": int(offline), "covered_s": int(covered),
            "availability_pct": round(100 * (covered - offline) / covered, 2) if covered else None,
            "drops_per_day": round(len(drops) * 86400 / covered, 1) if covered >= 3600 else None,
            "lqi_avg": round(sm["avg"]) if sm else d["lqi"], "lqi_min": sm["min"] if sm else None,
            "lqi_last": d["lqi"], "battery": d["battery"], "last_msg": d["last_msg"],
            "errors": {**{k: er.get(k, 0) for k in ("delivery", "route", "interview", "other")},
                       "total": sum(er.values())},
            "announces": ev_counts.get((d["ieee"], "device_announce"), 0),
            "leaves": ev_counts.get((d["ieee"], "device_leave"), 0),
            "parent": names.get(parent_of.get(d["ieee"])), "parent_lqi": parent_lqi.get(d["ieee"]),
            "strip": _strip(segs, start, end),
            "offline_intervals": [[s, e] for s, e, on in segs if not on][:12],
        })
    rows.sort(key=lambda r: (-r["drops"], -r["offline_s"], r["name"].lower()))

    # -- coupures simultanées
    with_data = sum(1 for s in all_segs.values() if s)
    clusters = []
    for g in find_clusters(all_drops, with_data):
        t0, t1 = g[0][0], g[-1][0]
        members = sorted({i for _, i in g})
        back = []
        for i in members:                       # retour mesuré depuis la chute de chaque appareil
            fell = min(t for t, j in g if j == i)
            nxt = [s for s, _, on in all_segs[i] if on and s > fell]
            if nxt:
                back.append(min(nxt) - fell)
        routers = [names[i] for i in members if by_ieee[i]["type"] == "Router"]
        pcount: dict[str, int] = {}
        for i in members:
            p = parent_of.get(i)
            if p:
                pcount[p] = pcount.get(p, 0) + 1
        top_parent = max(pcount.items(), key=lambda kv: kv[1], default=None)
        shared = names.get(top_parent[0]) if top_parent and top_parent[1] >= max(2, 0.6 * len(members)) else None
        bridge = any(s - CLUSTER_GAP <= t1 and t0 <= e + CLUSTER_GAP for s, e in bridge_out)
        from_ha = any(r["src"] == "ha" for i in members for r in inwin.get(i, []) if t0 - 5 <= r["ts"] <= t1 + 5)
        is_global = len(members) >= max(3, 0.8 * with_data)
        clusters.append({
            "ts": t0, "n": len(members), "of": with_data, "devices": [names[i] for i in members],
            "routers": routers, "shared_parent": shared, "from_ha": from_ha,
            "cause": "bridge" if bridge else "global" if is_global else "group",
            "back_after_s": int(statistics.median(back)) if back else None,
        })

    # -- chronologie : appareils hors ligne à un instant donné
    step = max(300, window // STRIP_CELLS)
    timeline = []
    for t in range(start, end, step):
        off = sum(1 for segs in all_segs.values()
                  if any(not on and _overlap(s, e, t, t + step) > 0 for s, e, on in segs))
        timeline.append({"ts": t, "offline": off})

    findings = _findings(rows, clusters, bridge_out, info, netmap, with_data, devs)
    findings.sort(key=lambda f: SEVERITY_RANK[f["severity"]])

    total_cov = sum(r["covered_s"] for r in rows)
    total_off = sum(r["offline_s"] for r in rows)
    hours_cov = (end - covered_since) / 3600 if covered_since else 0
    recent = db.q("SELECT ts, kind, level, ieee, cat, message FROM z2m_log WHERE ts >= ? AND ts <= ? "
                  "ORDER BY ts DESC LIMIT 60", [start, end])
    for r in recent:
        r["device"] = names.get(r["ieee"])
    return {
        "start": start, "end": end, "window_hours": round(window / 3600, 1),
        "coverage": {"since": covered_since, "hours": round(hours_cov, 1),
                     "complete": bool(covered_since and covered_since <= start + window * 0.05)},
        "summary": {
            "devices": len(devs), "with_data": with_data,
            "online": sum(1 for r in rows if r["online"] is True), "offline": sum(1 for r in rows if r["online"] is False),
            "drops": sum(r["drops"] for r in rows), "flapping": sum(1 for r in rows if r["drops"] >= FLAP_WARN),
            "availability_pct": round(100 * (total_cov - total_off) / total_cov, 2) if total_cov else None,
            "bridge_outages": len(bridge_out), "clusters": len(clusters),
            "errors": sum(v for e in errs.values() for v in e.values()),
        },
        "verdict": _verdict(findings, rows, with_data),
        "findings": findings, "clusters": sorted(clusters, key=lambda c: c["ts"]), "devices": rows,
        "timeline": timeline, "log": recent, "info": info,
        "networkmap_ts": (netmap or {}).get("ts"),
    }


# ------------------------------------------------------------------ constats
def _f(key, severity, title, detail, suggestion, devices=None) -> dict:
    return {"key": key, "severity": severity, "title": title, "detail": detail,
            "suggestion": suggestion, "devices": devices or []}


def _findings(rows, clusters, bridge_out, info, netmap, with_data, devs) -> list[dict]:
    out: list[dict] = []
    info = info or {}
    routers = [d for d in devs if d["type"] == "Router"]
    end_devs = [d for d in devs if d["type"] == "EndDevice"]

    # disponibilité non publiée
    if not with_data and devs:
        if info.get("availability_enabled") is False:
            out.append(_f("no_availability", "warning", "La disponibilité n'est pas activée dans Zigbee2MQTT",
                          "Sans elle, Zigbee2MQTT ne publie pas l'état en ligne/hors ligne des appareils : "
                          "impossible de compter les déconnexions.",
                          "Ajoutez « availability: true » dans configuration.yaml (ou Paramètres → Disponibilité), "
                          "redémarrez Zigbee2MQTT, puis laissez tourner quelques heures."))
        else:
            out.append(_f("no_data", "info", "Pas encore de données de disponibilité",
                          "Aucun changement d'état reçu depuis l'activation du module.",
                          "Laissez tourner (24 h pour un diagnostic complet) ou importez l'historique de Home Assistant."))

    # pont Zigbee2MQTT
    if bridge_out:
        total = sum(e - s for s, e in bridge_out)
        out.append(_f("bridge_down", "critical", f"Zigbee2MQTT s'est arrêté {len(bridge_out)} fois",
                      f"Pont hors ligne pendant {_dur(total)} au total : tous les appareils sont injoignables pendant ce temps.",
                      "Consultez les journaux de Zigbee2MQTT au moment des coupures : plantage, redémarrage du conteneur/hôte, "
                      "adaptateur USB débranché ou en erreur, broker MQTT redémarré."))

    # coupures simultanées
    glob = [c for c in clusters if c["cause"] == "global"]
    grp = [c for c in clusters if c["cause"] == "group"]
    if glob:
        ha = any(c["from_ha"] for c in glob)
        out.append(_f("global_outage", "critical", f"{len(glob)} coupure(s) simultanée(s) de presque tout le réseau",
                      "Plus de 80 % des appareils tombent en même temps puis reviennent : la cause est commune, "
                      "pas les appareils. " + ("Ces données viennent de Home Assistant : un redémarrage de HA ou de "
                                               "l'intégration MQTT produit le même effet. " if ha else ""),
                      "Suspectez le coordinateur : adaptateur sur un port USB 3.0 ou collé à la box/au NAS (utilisez une "
                      "rallonge USB 2.0 d'au moins 50 cm), alimentation USB instable, mise à jour du firmware du "
                      "coordinateur. Vérifiez aussi les redémarrages du broker MQTT ou de la machine hôte."))
    if grp:
        sized = sorted(grp, key=lambda c: -c["n"])[:3]
        detail = " ; ".join(f"{c['n']} appareils ({', '.join(c['devices'][:4])}{'…' if c['n'] > 4 else ''})"
                            + (f", parent commun « {c['shared_parent']} »" if c["shared_parent"] else
                               f", routeur(s) concerné(s) : {', '.join(c['routers'])}" if c["routers"] else "")
                            for c in sized)
        out.append(_f("group_drops", "warning", f"{len(grp)} coupure(s) de groupes d'appareils",
                      "Des appareils tombent ensemble : " + detail + ".",
                      "Un routeur commun qui lâche entraîne ses enfants : vérifiez son alimentation et son firmware. "
                      "Sinon, une interférence ponctuelle (Wi-Fi, micro-ondes, USB 3.0) est probable. "
                      "Lancez la carte du réseau pour identifier le parent de chaque appareil.",
                      sorted({n for c in sized for n in c["devices"]})))

    # appareils instables
    flap = [r for r in rows if r["drops"] >= FLAP_WARN and (r["drops_per_day"] or 0) >= FLAP_WARN]
    for r in flap[:8]:
        crit = r["drops"] >= FLAP_CRIT and (r["drops_per_day"] or 0) >= FLAP_CRIT
        weak = r["lqi_avg"] is not None and r["lqi_avg"] < LQI_WEAK
        hints = []
        if r["type"] == "EndDevice" or (r["power"] or "").lower().startswith("battery"):
            hints.append("Changez la pile (une tension faible provoque des pertes), rapprochez l'appareil ou ajoutez "
                         "un routeur alimenté sur secteur (prise ou ampoule Zigbee) entre lui et le coordinateur.")
        else:
            hints.append("Vérifiez son alimentation (interrupteur mural coupé, prise ou rallonge instable) et son firmware : "
                         "un routeur qui tombe fait aussi tomber les appareils qui passent par lui.")
        if weak:
            hints.append(f"Son lien est faible (LQI moyen {r['lqi_avg']}/255) : c'est probablement la cause.")
        if r["announces"] >= 3:
            hints.append(f"Il s'est ré-annoncé {r['announces']} fois : il redémarre ou se rattache sans cesse.")
        out.append(_f(f"flap:{r['ieee']}", "critical" if crit else "warning",
                      f"{r['name']} : {r['drops']} déconnexions",
                      f"Hors ligne {_dur(r['offline_s'])} au total ({r['availability_pct']} % de disponibilité)."
                      + (f" Parent : {r['parent']}." if r["parent"] else ""),
                      " ".join(hints), [r["name"]]))
    if len(flap) > 8:
        out.append(_f("flap_more", "warning", f"{len(flap) - 8} autres appareils instables",
                      ", ".join(r["name"] for r in flap[8:]), "Voir le tableau des appareils.",
                      [r["name"] for r in flap[8:]]))

    # liens faibles
    weak_rows = sorted((r for r in rows if r["lqi_avg"] is not None and r["lqi_avg"] < LQI_WEAK),
                       key=lambda r: r["lqi_avg"])
    if weak_rows:
        out.append(_f("weak_links", "warning", f"{len(weak_rows)} appareil(s) avec un lien faible",
                      ", ".join(f"{r['name']} ({r['lqi_avg']})" for r in weak_rows[:10]) +
                      ". Le LQI va de 0 à 255 ; sous 50, les paquets se perdent facilement.",
                      "Ajoutez un routeur sur secteur à mi-chemin, rapprochez l'appareil, éloignez le coordinateur des "
                      "sources d'interférence (rallonge USB 2.0, à distance de la box et du NAS).",
                      [r["name"] for r in weak_rows]))

    # piles faibles
    low = sorted((r for r in rows if r["battery"] is not None and r["battery"] <= BATTERY_LOW), key=lambda r: r["battery"])
    if low:
        out.append(_f("low_battery", "warning", f"{len(low)} pile(s) faible(s)",
                      ", ".join(f"{r['name']} ({r['battery']} %)" for r in low),
                      "Remplacez-les : une pile faible est une cause classique de déconnexions intermittentes.",
                      [r["name"] for r in low]))

    # erreurs de transmission
    bad = sorted((r for r in rows if r["errors"]["delivery"] + r["errors"]["route"] >= 5),
                 key=lambda r: -(r["errors"]["delivery"] + r["errors"]["route"]))
    if bad:
        out.append(_f("comm_errors", "warning", f"Erreurs de transmission sur {len(bad)} appareil(s)",
                      ", ".join(f"{r['name']} ({r['errors']['delivery'] + r['errors']['route']})" for r in bad[:8]) +
                      " — « delivery failed », pas d'acquittement ou route introuvable.",
                      "Ce sont les symptômes d'un lien radio dégradé : mêmes remèdes que pour les liens faibles "
                      "(routeur intermédiaire, repositionnement, interférences).",
                      [r["name"] for r in bad]))

    # topologie
    if len(end_devs) >= 8 and len(routers) <= max(1, len(end_devs) // 8):
        out.append(_f("few_routers", "warning", "Très peu de routeurs pour le nombre d'appareils",
                      f"{len(routers)} routeur(s) pour {len(end_devs)} appareils sur pile.",
                      "Ajoutez des routeurs Zigbee alimentés sur secteur (prises connectées, ampoules) répartis dans "
                      "la maison : ils relaient le signal et soulagent le coordinateur."))
    if netmap:
        kids: dict[str, int] = {}
        for lk in netmap["links"]:
            if lk.get("rel") == 1:
                kids[lk["src"]] = kids.get(lk["src"], 0) + 1
        nm_names = {n["ieee"]: n.get("name") or n["ieee"] for n in netmap["nodes"]}
        heavy = [(nm_names.get(i, i), n) for i, n in kids.items() if n >= 20]
        if heavy:
            out.append(_f("overloaded_parent", "warning", "Un nœud porte beaucoup d'appareils directs",
                          ", ".join(f"{n} : {k} enfants" for n, k in heavy),
                          "Au-delà d'une vingtaine d'enfants directs, un coordinateur ou un routeur devient fragile : "
                          "répartissez-les en ajoutant des routeurs."))

    # canal Zigbee vs Wi-Fi
    ch = info.get("channel")
    if isinstance(ch, int) and 11 <= ch <= 26:
        wifi = _channel_overlap(ch)
        if wifi:
            out.append(_f("channel", "warning", f"Canal Zigbee {ch} : recouvre le Wi-Fi 2,4 GHz canal {wifi}",
                          "Le Wi-Fi est la première cause d'interférence Zigbee. Le canal actuel chevauche les "
                          "canaux Wi-Fi les plus utilisés (1, 6, 11).",
                          "Passez sur le canal 15, 20 ou 25 (Zigbee2MQTT → Paramètres → Réseau). Les appareils sur secteur "
                          "suivent ; certains appareils sur pile peuvent devoir être ré-appairés."))
    return out


def _verdict(findings: list[dict], rows: list[dict], with_data: int) -> dict:
    keys = {f["key"].split(":")[0] for f in findings}
    if "no_availability" in keys or "no_data" in keys or not with_data:
        return {"severity": "info", "text": "Pas assez de données de disponibilité pour conclure."}
    if "global_outage" in keys:
        return {"severity": "critical",
                "text": "Tout le réseau tombe en même temps : le coordinateur (ou son alimentation USB) est le principal suspect."}
    if "bridge_down" in keys:
        return {"severity": "critical",
                "text": "Cause principale probable : Zigbee2MQTT lui-même s'arrête ou redémarre."}
    if "group_drops" in keys or "flap" in keys or "flap_more" in keys:
        n = sum(1 for r in rows if r["drops"] >= FLAP_WARN)
        return {"severity": "warning",
                "text": f"Problème localisé : {n} appareil(s) instable(s)"
                        + (", avec des coupures groupées (routeur commun ou interférence)." if "group_drops" in keys else ".")}
    if findings:
        return {"severity": "warning", "text": "Pas de déconnexions répétées, mais des points de fragilité sont signalés."}
    return {"severity": "good", "text": "Aucune anomalie détectée sur la période."}
