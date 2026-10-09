"""Réglages modifiables depuis l'interface. Les valeurs sont stockées dans la table meta
(clé `cfg:<nom>`) et appliquées au Config en direct : la plupart des boucles relisent
`cfg.X` à chaque itération, donc un changement prend effet au cycle suivant. Quelques
réglages nécessitent un redémarrage (marqués `restart`).

Les secrets (mots de passe, jetons, identifiants SSH) ne sont pas gérés ici.
"""
from __future__ import annotations

import ipaddress
import logging
import re

log = logging.getLogger("netwatch.settings")

# Garde-fous : un réglage hors de ces bornes est refusé dans l'interface, et ramené dans les bornes
# au démarrage (y compris s'il vient d'une variable d'environnement). Ils évitent surtout de saturer
# le réseau : découverte trop fréquente, trop de pings, trop de scans nmap en parallèle…
LIMITS = {
    "discovery_interval": (30, 86400), "ping_count": (1, 10), "ping_timeout": (0.2, 5.0),
    "offline_after": (1, 60), "deep_interval": (900, 2592000), "nmap_concurrency": (1, 8),
    "ssh_max_attempts": (1, 5), "ssh_retry_after": (600, 2592000), "ssh_timeout": (2.0, 60.0),
    "latency_warn_ms": (1.0, 10000.0), "external_latency_warn_ms": (1.0, 10000.0),
    "loss_warn_pct": (1.0, 100.0), "anomaly_factor": (1.2, 100.0), "anomaly_margin_ms": (0.0, 10000.0),
    "diag_interval": (600, 2592000), "diag_ping_count": (3, 100), "bufferbloat_seconds": (2.0, 30.0),
    "box_interval": (30, 3600), "mqtt_port": (1, 65535), "conflict_window": (60, 86400),
}
CSV_MAX = {"external_targets": 8, "exclude": 64, "diag_dns_servers": 6, "diag_tcp_targets": 6, "notify_types": 60}
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$")


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _is_host(v: str) -> bool:
    return _is_ip(v) or bool(_HOST.match(v))


def _check(key: str, typ: str, value):
    """Contrôle une valeur déjà convertie. Lève ValueError avec un message lisible."""
    if key in LIMITS:
        lo, hi = LIMITS[key]
        if not lo <= value <= hi:
            raise ValueError(f"doit être entre {lo} et {hi}")
    if typ == "csv" and len(value) > CSV_MAX.get(key, 32):
        raise ValueError(f"{CSV_MAX.get(key, 32)} valeurs au maximum")
    if typ == "str" and (len(value) > 300 or any(ord(c) < 32 for c in value)):
        raise ValueError("texte trop long ou caractères de contrôle")
    if key == "external_targets" and not all(_is_host(v) for v in value):
        raise ValueError("adresses IP ou noms d'hôte attendus")
    if key == "diag_dns_servers" and not all(_is_ip(v) for v in value):
        raise ValueError("adresses IP attendues")
    if key == "exclude":
        for v in value:
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError as e:
                raise ValueError(f"« {v} » n'est ni une IP ni un CIDR") from e
    if key == "diag_tcp_targets":
        for v in value:
            host, _, port = v.rpartition(":")
            if not (_is_host(host) and port.isdigit() and 1 <= int(port) <= 65535):
                raise ValueError(f"« {v} » : hôte:port attendu")
    if key == "notify_types" and not all(re.fullmatch(r"[a-z0-9_]{1,40}", v) for v in value):
        raise ValueError("types d'événements invalides")
    if key == "nmap_args":
        from .nmapscan import safe_args
        safe_args(value)
    if key == "bufferbloat_url" and value and not re.match(r"^https?://[^\s]+$", value):
        raise ValueError("URL http(s) attendue")
    if key == "diag_dns_domain" and not _HOST.match(value):
        raise ValueError("nom de domaine invalide")
    if key == "mqtt_host" and value and not _is_host(value):
        raise ValueError("adresse du broker invalide")
    if key == "z2m_topic" and not re.fullmatch(r"[\w\-./]{1,64}", value):
        raise ValueError("topic invalide (lettres, chiffres, - _ . / ; pas de joker # ou +)")
    if key == "box_host" and value:
        from .boxes import host_allowed
        if not host_allowed(value):
            raise ValueError("adresse privée ou nom de box connu uniquement")
    if key == "ha_url" and value:
        from .hahistory import url_allowed
        if not url_allowed(value):
            raise ValueError("URL locale uniquement (le jeton ne part pas sur Internet)")
    return value

# (clé, type, groupe, libellé, aide, restart)
#   type : int | float | bool | str | csv
SPECS = [
    ("scans_enabled", "bool", "Découverte", "Scans automatiques activés", "Désactivé : plus de découverte ARP/ping ni de scan nmap automatique (les scans manuels restent possibles).", False),
    ("discovery_interval", "int", "Découverte", "Intervalle de découverte (s)", "Scan ARP + ping.", False),
    ("ping_count", "int", "Découverte", "Nombre de pings", "", False),
    ("ping_timeout", "float", "Découverte", "Délai de ping (s)", "", False),
    ("offline_after", "int", "Découverte", "Cycles manqués avant « hors ligne »", "", False),
    ("external_targets", "csv", "Découverte", "Cibles Internet", "IP séparées par des virgules.", False),
    ("exclude", "csv", "Découverte", "Hôtes exclus", "IP ou CIDR jamais scannés.", False),

    ("deep_enabled", "bool", "Scan approfondi", "Scan nmap (ports, services, OS) activé", "", False),
    ("deep_interval", "int", "Scan approfondi", "Intervalle nmap (s)", "", False),
    ("nmap_args", "str", "Scan approfondi", "Arguments nmap", "", False),
    ("nmap_concurrency", "int", "Scan approfondi", "Scans nmap en parallèle", "Prend effet au redémarrage.", True),

    ("ssh_enabled", "bool", "Inventaire SSH", "Inventaire SSH activé", "", False),
    ("ssh_known_only", "bool", "Inventaire SSH", "Mots de passe SSH réservés aux appareils approuvés", "Évite de présenter un mot de passe à un appareil inconnu qui ouvrirait le port 22.", False),
    ("ssh_max_attempts", "int", "Inventaire SSH", "Identifiants essayés par hôte/cycle", "Anti fail2ban.", False),
    ("ssh_retry_after", "int", "Inventaire SSH", "Délai avant de réessayer un refus (s)", "", False),
    ("ssh_timeout", "float", "Inventaire SSH", "Délai de connexion SSH (s)", "", False),

    ("latency_warn_ms", "float", "Alertes", "Seuil latence LAN (ms)", "", False),
    ("external_latency_warn_ms", "float", "Alertes", "Seuil latence Internet (ms)", "", False),
    ("loss_warn_pct", "float", "Alertes", "Seuil de perte (%)", "", False),
    ("anomaly_factor", "float", "Alertes", "Facteur d'anomalie de latence", "Latence 5 min > référence × facteur.", False),
    ("anomaly_margin_ms", "float", "Alertes", "Marge d'anomalie (ms)", "", False),
    ("notify_types", "csv", "Alertes", "Types d'événements notifiés (ntfy/MQTT)", "", False),

    ("diag_enabled", "bool", "Diagnostic", "Diagnostic de latence planifié", "", False),
    ("diag_interval", "int", "Diagnostic", "Intervalle de diagnostic (s)", "", False),
    ("diag_ping_count", "int", "Diagnostic", "Pings du diagnostic", "", False),
    ("diag_dns_domain", "str", "Diagnostic", "Domaine de test DNS", "", False),
    ("diag_dns_servers", "csv", "Diagnostic", "Résolveurs DNS testés", "", False),
    ("diag_tcp_targets", "csv", "Diagnostic", "Cibles TCP (hôte:port)", "", False),
    ("bufferbloat_url", "str", "Diagnostic", "URL de test bufferbloat", "Vide = désactivé.", False),
    ("bufferbloat_seconds", "float", "Diagnostic", "Durée du test bufferbloat (s)", "", False),

    ("box_enabled", "bool", "Box Internet", "Supervision de la box activée", "Bouygues, Free, Orange ou SFR. Les identifiants se saisissent dans la page Box.", False),
    ("box_host", "str", "Box Internet", "Adresse de la box", "Vide = passerelle détectée (IP privée ou nom de box connu).", False),
    ("box_interval", "int", "Box Internet", "Intervalle d'interrogation (s)", "", False),
    ("wifi_tracking", "bool", "Box Internet", "Suivi Wi-Fi (coupures, itinérance)", "S'appuie sur la liste d'appareils de la box.", False),

    ("z2m_enabled", "bool", "Zigbee2MQTT", "Diagnostic Zigbee2MQTT activé", "Le mot de passe MQTT se saisit dans la page Zigbee.", False),
    ("z2m_topic", "str", "Zigbee2MQTT", "Topic de base de Zigbee2MQTT", "Par défaut : zigbee2mqtt.", False),
    ("mqtt_host", "str", "Zigbee2MQTT", "Broker MQTT (adresse)", "Sert aussi aux notifications MQTT.", False),
    ("mqtt_port", "int", "Zigbee2MQTT", "Broker MQTT (port)", "", False),
    ("mqtt_user", "str", "Zigbee2MQTT", "Broker MQTT (utilisateur)", "", False),
    ("ha_url", "str", "Zigbee2MQTT", "URL de Home Assistant", "Ex. http://192.168.1.11:8123 (import de l'historique). Le jeton se saisit dans la page Zigbee.", False),

    ("ha_verify_tls", "bool", "Zigbee2MQTT", "Vérifier le certificat de Home Assistant", "Décochez si HA utilise un certificat auto-signé (HTTPS).", False),

    ("conflict_window", "int", "Conflits", "Fenêtre de conflit d'IP (s)", "", False),
]
SPEC_BY_KEY = {s[0]: s for s in SPECS}
_META_PREFIX = "cfg:"
# anciens noms (la box n'était que la Bbox) : les réglages déjà enregistrés restent valables
LEGACY = {"box_enabled": "bbox_enabled", "box_host": "bbox_host", "box_interval": "bbox_interval"}


def _coerce(typ: str, raw):
    if typ == "int":
        return int(raw)
    if typ == "float":
        return float(raw)
    if typ == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "yes", "on", "oui")
    if typ == "csv":
        if isinstance(raw, list):
            items = raw
        else:
            items = str(raw).split(",")
        return [x.strip() for x in items if str(x).strip()]
    return str(raw).strip()


def _to_store(typ: str, value) -> str:
    if typ == "csv":
        return ",".join(value)
    if typ == "bool":
        return "1" if value else "0"
    return str(value)


def load_overrides(cfg, db) -> None:
    """Applique les réglages persistés au Config au démarrage."""
    for key, typ, *_ in SPECS:
        raw = db.get_meta(_META_PREFIX + key)
        if raw is None and key in LEGACY:
            raw = db.get_meta(_META_PREFIX + LEGACY[key])
        if raw is None:
            continue
        try:
            setattr(cfg, key, _coerce(typ, raw))
        except (ValueError, TypeError) as e:
            log.warning("Réglage %s ignoré (%s)", key, e)
    sanitize(cfg)


def sanitize(cfg) -> None:
    """Ramène la configuration effective dans les garde-fous, quelle que soit sa provenance."""
    fallback = {"nmap_args": _nmap_default(), "diag_dns_domain": "example.com",
                "z2m_topic": "zigbee2mqtt"}
    for key, typ, *_ in SPECS:
        val = getattr(cfg, key, None)
        if val is None:
            continue
        if key in LIMITS and isinstance(val, (int, float)) and not isinstance(val, bool):
            lo, hi = LIMITS[key]
            if not lo <= val <= hi:
                new = type(val)(min(max(val, lo), hi))
                log.warning("Réglage %s=%s hors bornes : ramené à %s", key, val, new)
                setattr(cfg, key, new)
            continue
        try:
            _check(key, typ, val)
        except ValueError as e:
            log.warning("Réglage %s refusé (%s) : valeur par défaut rétablie", key, e)
            setattr(cfg, key, fallback.get(key, [] if typ == "csv" else ""))


def public(cfg) -> dict:
    """Schéma + valeurs courantes, pour l'API."""
    groups: dict[str, list] = {}
    for key, typ, group, label, help_, restart in SPECS:
        val = getattr(cfg, key, None)
        groups.setdefault(group, []).append({
            "key": key, "type": typ, "label": label, "help": help_, "restart": restart,
            "value": val,
        })
    return {"groups": [{"name": g, "settings": s} for g, s in groups.items()]}


def apply(cfg, db, body: dict) -> dict:
    """Valide, coerce, persiste et applique les changements. Retourne le détail."""
    applied: dict = {}
    errors: dict = {}
    restart = []
    for key, raw in body.items():
        spec = SPEC_BY_KEY.get(key)
        if not spec:
            continue
        typ = spec[1]
        try:
            value = _check(key, typ, _coerce(typ, raw))
        except (ValueError, TypeError) as e:
            errors[key] = str(e) if isinstance(e, ValueError) and str(e) and "invalid literal" not in str(e) \
                and "could not convert" not in str(e) else "valeur invalide"
            continue
        setattr(cfg, key, value)
        db.set_meta(_META_PREFIX + key, _to_store(typ, value))
        applied[key] = value
        if spec[5]:
            restart.append(key)
    return {"applied": applied, "errors": errors, "restart_needed": restart}


def _nmap_default() -> str:
    from .nmapscan import DEFAULT_ARGS
    return DEFAULT_ARGS
