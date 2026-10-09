"""Diagnostic de latence réseau : mesures actives + historique → constats et verdict.

Chaque constat (finding) porte une clé stable : il reste « actif » tant qu'il est observé
et un événement n'est émis qu'à sa première apparition. Les fonctions d'analyse sont pures
(dictionnaires en entrée) afin d'être testables sans réseau.
"""
from __future__ import annotations

import logging
import statistics
from collections import defaultdict

log = logging.getLogger("netwatch.diag")

SEV_WEIGHT = {"info": 0, "warning": 2, "critical": 5}
ORIGINS = {
    "wan": "Connexion Internet / fournisseur d'accès",
    "gateway": "Box / routeur (passerelle)",
    "lan": "Réseau local (switch, câblage)",
    "wifi": "Wi-Fi",
    "device": "Un ou plusieurs appareils",
    "dns": "Résolution DNS",
    "bufferbloat": "Saturation de la connexion (bufferbloat)",
    "mtu": "MTU / fragmentation",
    "scanner": "Machine de mesure (NetWatch)",
}


def finding(key, category, severity, title, detail="", suggestion="", evidence=None, device_id=None):
    return {"key": "net:" + key, "category": category, "severity": severity, "title": title,
            "detail": detail, "suggestion": suggestion, "evidence": evidence or {}, "device_id": device_id}


def median(values):
    v = [x for x in values if x is not None]
    return statistics.median(v) if v else None


def spike_threshold(baseline, factor, margin):
    return None if baseline is None else max(baseline * factor, baseline + margin)


# ====================================================================== traceroute
def traceroute_analysis(hops, jump_ms=15.0):
    """Repère le premier saut où la latence augmente durablement : le retard doit se
    retrouver aux sauts suivants (un routeur lent à répondre à l'ICMP sans rien retarder
    en aval ne compte pas). Retourne le saut fautif ou None."""
    pts = [(h["ttl"], h["avg"], h.get("ip")) for h in hops if h.get("avg") is not None]
    if len(pts) < 2:
        return None
    for i in range(1, len(pts)):
        prev_best = min(p[1] for p in pts[:i])
        downstream = [p[1] for p in pts[i:]]
        if pts[i][1] - prev_best >= jump_ms and min(downstream) - prev_best >= jump_ms * 0.7:
            ttl = pts[i][0]
            segment = "box" if ttl == 1 else "fai" if ttl <= 3 else "transit"
            return {"ttl": ttl, "ip": pts[i][2], "increase": round(pts[i][1] - prev_best, 1), "segment": segment}
    return None


# ====================================================================== corrélation historique
def correlate_spikes(series, baselines, factor, margin, min_devices=4, share=0.5):
    """series = {device_id: {minute: latence}}. Une minute est « généralisée » quand au moins
    `share` des appareils mesurés y dépassent leur propre seuil : cela pointe une cause commune
    (box, switch, lien montant) plutôt qu'un appareil isolé."""
    per_minute = defaultdict(list)
    measured = defaultdict(int)
    over_by_device = defaultdict(int)
    minutes_by_device = defaultdict(int)
    for did, pts in series.items():
        thr = spike_threshold(baselines.get(did), factor, margin)
        if thr is None:
            continue
        for minute, lat in pts.items():
            if lat is None:
                continue
            measured[minute] += 1
            minutes_by_device[did] += 1
            if lat > thr:
                per_minute[minute].append(did)
                over_by_device[did] += 1
    generalized = sorted(m for m, ids in per_minute.items()
                         if measured[m] >= min_devices and len(ids) / measured[m] >= share)
    frequent = {did: round(n / minutes_by_device[did], 3) for did, n in over_by_device.items()
                if minutes_by_device[did] >= 10 and n / minutes_by_device[did] >= 0.2}
    return {"generalized_minutes": generalized, "frequent_devices": frequent,
            "generalized_count": len(generalized)}


# ====================================================================== construction des constats
def _ms(v):
    return "—" if v is None else f"{v:.1f} ms"


def scanner_findings(me):
    out = []
    if me.get("load") and me.get("cores") and me["load"][0] > me["cores"] * 1.5:
        out.append(finding("scanner:load", "scanner", "warning", "Machine NetWatch surchargée",
                           f"Charge {me['load'][0]:.1f} pour {me['cores']} cœur(s) : les mesures peuvent être faussées.",
                           "Vérifiez les autres charges de la VM ou allouez-lui plus de CPU.", {"load": me["load"]}))
    if me.get("duplex") == "half":
        out.append(finding("scanner:duplex", "lan", "critical", "Carte réseau de NetWatch en half-duplex",
                           "Un lien half-duplex provoque collisions et latence irrégulière sur toutes les mesures.",
                           "Vérifiez le câble et forcez auto/auto des deux côtés du port de switch.", me))
    counters = me.get("counters") or {}
    errs = counters.get("rx_errs", 0) + counters.get("tx_errs", 0) + counters.get("rx_drop", 0)
    if errs > 0:
        out.append(finding("scanner:iface_errors", "lan", "warning", "Erreurs sur la carte réseau de NetWatch",
                           f"{errs} erreur(s)/perte(s) au niveau de l'interface de mesure.",
                           "Câble ou port de switch suspect côté machine NetWatch.", counters))
    if me.get("wireless"):
        out.append(finding("scanner:wifi", "scanner", "info", "NetWatch mesure via le Wi-Fi",
                           "La machine de mesure est elle-même en Wi-Fi : la gigue observée peut venir de sa liaison.",
                           "Pour un diagnostic fiable, raccordez NetWatch en Ethernet.", {}))
    return out


def wan_findings(ext, gateway_ok, ext_warn_ms):
    """ext = {ip: stats ping}. Distingue un problème Internet d'un problème local :
    latence externe élevée alors que la passerelle répond bien = côté FAI/Internet."""
    out = []
    reachable = {ip: s for ip, s in ext.items() if s.get("recv")}
    if not reachable and ext:
        out.append(finding("wan:down", "wan", "critical", "Aucune cible Internet joignable",
                           f"Les {len(ext)} cible(s) externe(s) ne répondent pas.",
                           "Vérifiez la connexion Internet et l'état de la box.", {"targets": list(ext)}))
        return out
    high = {ip: s for ip, s in reachable.items() if (s.get("avg") or 0) > ext_warn_ms}
    lossy = {ip: s for ip, s in reachable.items() if (s.get("loss") or 0) >= 5}
    if high and gateway_ok:
        worst = max(high.values(), key=lambda s: s["avg"])
        out.append(finding("wan:latency", "wan", "warning", "Latence Internet élevée, réseau local sain",
                           f"Latence externe jusqu'à {_ms(worst['avg'])} alors que la passerelle répond normalement : "
                           "le retard est en aval de la box.",
                           "Côté fournisseur d'accès ou lien WAN. Un traceroute précise le saut concerné.",
                           {"targets": {ip: s["avg"] for ip, s in high.items()}}))
    if lossy:
        worst = max(lossy.values(), key=lambda s: s["loss"])
        out.append(finding("wan:loss", "wan", "critical", "Perte de paquets vers Internet",
                           f"Jusqu'à {worst['loss']:.0f} % de perte vers l'extérieur.",
                           "Perte typique d'un lien WAN saturé ou instable (câble coaxial/fibre, ligne).",
                           {"targets": {ip: s["loss"] for ip, s in lossy.items()}}))
    jit = {ip: s for ip, s in reachable.items() if (s.get("jitter") or 0) > 20}
    if jit and gateway_ok:
        out.append(finding("wan:jitter", "wan", "warning", "Gigue importante vers Internet",
                           f"Gigue jusqu'à {_ms(max(s['jitter'] for s in jit.values()))} : gêne la visio et le jeu.",
                           "Souvent un signe de bufferbloat ou de lien WAN chargé.",
                           {ip: s["jitter"] for ip, s in jit.items()}))
    return out


def gateway_findings(gw_stats, lan_warn_ms):
    out = []
    if not gw_stats:
        return out
    if not gw_stats.get("recv"):
        out.append(finding("gateway:down", "gateway", "critical", "Passerelle injoignable",
                           "La box/routeur ne répond pas au ping : tout le trafic sortant est affecté.",
                           "Vérifiez la box (redémarrage récent ?) et le lien entre elle et NetWatch.", gw_stats))
    elif (gw_stats.get("avg") or 0) > max(5.0, lan_warn_ms):
        out.append(finding("gateway:latency", "gateway", "warning", "Passerelle lente à répondre",
                           f"Latence vers la passerelle : {_ms(gw_stats['avg'])} (attendu < 5 ms en filaire).",
                           "Box surchargée, Wi-Fi entre NetWatch et la box, ou lien local dégradé.", gw_stats))
    elif (gw_stats.get("loss") or 0) > 0:
        out.append(finding("gateway:loss", "lan", "critical", "Perte de paquets vers la passerelle",
                           f"{gw_stats['loss']:.0f} % de perte sur le lien local vers la box : problème LAN.",
                           "Câble, port de switch ou interférence Wi-Fi entre NetWatch et la box.", gw_stats))
    return out


def dns_findings(dns_results):
    """dns_results = liste de dicts issus de probes.dns_probe."""
    out = []
    for d in dns_results:
        srv = d["server"]
        if not d.get("ok"):
            out.append(finding(f"dns:down:{srv}", "dns", "warning", f"Résolveur DNS {srv} muet",
                               "Le serveur DNS ne répond pas : navigation qui « rame » avant chaque site.",
                               "Retirez ce résolveur ou vérifiez sa configuration.", d))
            continue
        if (d.get("cached_ms") or 0) > 50:
            out.append(finding(f"dns:slow:{srv}", "dns", "warning", f"Résolveur DNS {srv} lent",
                               f"Réponse en cache en {_ms(d['cached_ms'])} (attendu < 20 ms).",
                               "Un résolveur local (box, Pi-hole) répond en général en quelques ms.", d))
        elif (d.get("uncached_ms") or 0) > 300:
            out.append(finding(f"dns:uncached:{srv}", "dns", "info", f"DNS récursif lent via {srv}",
                               f"Résolution hors cache en {_ms(d['uncached_ms'])}.",
                               "Normal pour un DNS public éloigné ; un cache local accélère les premières visites.", d))
    return out


def bufferbloat_findings(bb):
    if not bb or bb.get("increase") is None:
        return []
    grade, inc = bb.get("grade"), bb["increase"]
    if grade in ("A+", "A", "B"):
        return [finding("bufferbloat", "bufferbloat", "info", f"Bufferbloat maîtrisé (note {grade})",
                        f"Sous charge, la latence n'augmente que de {_ms(inc)}.",
                        "", bb)]
    sev = "critical" if grade == "F" else "warning"
    return [finding("bufferbloat", "bufferbloat", sev, f"Bufferbloat détecté (note {grade})",
                    f"Sous charge (téléchargement à {bb.get('mbps')} Mb/s), la latence bondit de {_ms(inc)}. "
                    "C'est la cause n°1 des saccades en visio/jeu quand quelqu'un télécharge.",
                    "Activez la gestion de file d'attente (SQM/fq_codel) sur la box ou le routeur, "
                    "ou limitez le débit à ~90 % de la ligne.", bb)]


def mtu_findings(mtu):
    if not mtu or not mtu.get("ok") or not mtu.get("mtu"):
        return []
    m = mtu["mtu"]
    if m < 1500 and m not in (1492,):
        return [finding("mtu", "mtu", "info", f"MTU de chemin inhabituel ({m})",
                        f"Le plus gros paquet passant sans fragmentation est de {m} octets (Ethernet standard : 1500).",
                        "Un MTU réduit ralentit certains transferts. Vérifiez PPPoE (1492) ou une encapsulation VPN.",
                        mtu)]
    return []


def latency_verdict(findings, correlation, ext_high):
    """Synthétise un verdict lisible : origine la plus probable et gravité globale."""
    by_origin = defaultdict(int)
    for f in findings:
        by_origin[f["category"]] += SEV_WEIGHT.get(f["severity"], 1)
    # une latence généralisée sur beaucoup d'appareils pointe une cause commune
    if correlation and correlation.get("generalized_count", 0) >= 3:
        by_origin["lan"] += 3
    origin = max(by_origin, key=by_origin.get) if by_origin else None
    max_sev = "info"
    for f in findings:
        if SEV_WEIGHT.get(f["severity"], 0) > SEV_WEIGHT.get(max_sev, 0):
            max_sev = f["severity"]
    if not findings:
        summary = "Aucun problème de latence détecté sur cette exécution."
    elif origin:
        summary = f"Origine la plus probable : {ORIGINS.get(origin, origin)}."
    else:
        summary = "Anomalies détectées, origine indéterminée."
    return {"origin": origin, "origin_label": ORIGINS.get(origin) if origin else None,
            "severity": max_sev, "summary": summary,
            "scores": {k: v for k, v in sorted(by_origin.items(), key=lambda x: -x[1])}}
