"""Analyse d'exposition : à partir des ports ouverts et des versions détectées par nmap,
produit des constats de sécurité (services en clair, bases de données ouvertes, versions
anciennes, surface d'attaque). Heuristique volontairement prudente — ce n'est pas un
scanner de CVE, mais un garde-fou pour repérer l'évident.

Fonction pure `analyze(device, open_ports)` : testable sans réseau.
"""
from __future__ import annotations

import re

# Services en clair / d'administration risqués : port -> (sévérité, titre, détail, conseil)
RISKY_PORTS = {
    23: ("critical", "Telnet exposé", "Telnet transmet identifiants et données en clair.",
         "Désactive Telnet et utilise SSH."),
    21: ("warning", "FTP exposé", "FTP transmet les identifiants en clair (sauf FTPS).",
         "Préfère SFTP/FTPS, ou restreins l'accès."),
    512: ("critical", "Service r-exec exposé", "rexec/rlogin/rsh sont non chiffrés et obsolètes.",
          "Désactive les r-services."),
    513: ("critical", "Service rlogin exposé", "rlogin est non chiffré et obsolète.", "Désactive rlogin."),
    514: ("critical", "Service rsh exposé", "rsh est non chiffré et obsolète.", "Désactive rsh."),
    5900: ("warning", "VNC exposé", "VNC est souvent sans chiffrement ni mot de passe fort.",
           "Passe par un tunnel SSH/VPN et impose un mot de passe."),
    3389: ("info", "RDP exposé", "Bureau à distance accessible sur le réseau.",
           "Limite l'accès et active l'authentification réseau (NLA)."),
    1521: ("warning", "Oracle DB exposée", "Base de données accessible sur le réseau.",
           "Restreins l'accès aux seuls hôtes autorisés."),
    2049: ("info", "NFS exposé", "Partage NFS accessible sur le réseau.",
           "Vérifie les exports et restreins par IP."),
    69: ("warning", "TFTP exposé", "TFTP est sans authentification.", "Désactive-le s'il n'est pas nécessaire."),
}

# Bases de données souvent laissées sans mot de passe
DB_PORTS = {
    3306: "MySQL/MariaDB", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
    9200: "Elasticsearch", 11211: "Memcached", 5984: "CouchDB", 8086: "InfluxDB",
    9000: "ClickHouse/divers",
}

# Versions minimales conseillées pour quelques produits courants (heuristique simple)
MIN_VERSIONS = {
    "openssh": (8, 0),
}


def _ver_tuple(version: str | None) -> tuple[int, ...] | None:
    if not version:
        return None
    m = re.match(r"(\d+)\.(\d+)", version)
    return (int(m.group(1)), int(m.group(2))) if m else None


def finding(key: str, severity: str, title: str, detail: str, suggestion: str,
            device_id: int, evidence: dict | None = None) -> dict:
    return {"key": key, "category": "security", "severity": severity, "title": title,
            "detail": detail, "suggestion": suggestion, "evidence": evidence or {}, "device_id": device_id}


def analyze(device: dict, open_ports: list[dict]) -> list[dict]:
    """Retourne les constats de sécurité pour un appareil (clés préfixées `sec:<id>:`)."""
    did = device["id"]
    label = device.get("alias") or device.get("hostname") or device.get("ip") or "appareil"
    tcp = [p for p in open_ports if (p.get("proto") or "tcp") == "tcp"]
    out: list[dict] = []
    base = f"sec:{did}:"

    for p in tcp:
        port = p["port"]
        pv = " ".join(x for x in (p.get("product"), p.get("version")) if x) or (p.get("service") or "")

        if port in RISKY_PORTS:
            sev, title, detail, sugg = RISKY_PORTS[port]
            out.append(finding(f"{base}risky:{port}", sev, f"{title} sur {label}",
                               f"Port {port} ouvert. {detail}", sugg, did, {"port": port, "service": pv}))

        if port in DB_PORTS:
            out.append(finding(f"{base}db:{port}", "warning", f"{DB_PORTS[port]} accessible sur le réseau",
                               f"Port {port} ({DB_PORTS[port]}) ouvert sur {label}. Beaucoup de bases sont "
                               "laissées sans authentification par défaut.",
                               "Vérifie qu'un mot de passe est exigé et restreins l'accès aux hôtes autorisés.",
                               did, {"port": port}))

        # version ancienne connue
        prod = (p.get("product") or "").lower()
        for name, minv in MIN_VERSIONS.items():
            if name in prod:
                vt = _ver_tuple(p.get("version"))
                if vt and vt < minv:
                    out.append(finding(f"{base}oldver:{port}", "warning",
                                       f"Version ancienne de {p.get('product')} sur {label}",
                                       f"{pv} sur le port {port} (conseillé ≥ {minv[0]}.{minv[1]}).",
                                       "Mets à jour le service ; les vieilles versions cumulent des failles connues.",
                                       did, {"port": port, "version": p.get("version")}))

    # interfaces d'administration HTTP non chiffrées (hors équipements web légitimes)
    http_ports = [p["port"] for p in tcp if (p.get("service") or "").startswith("http")
                  and "https" not in (p.get("service") or "") and p["port"] not in (80, 443)]
    has_https = any("https" in (p.get("service") or "") for p in tcp)
    if http_ports and not has_https and device.get("dev_type") not in ("server",):
        out.append(finding(f"{base}http_admin", "info", f"Interface HTTP non chiffrée sur {label}",
                           f"Ports HTTP sans HTTPS : {', '.join(map(str, sorted(http_ports)))}.",
                           "Si c'est une interface d'administration, active HTTPS.", did,
                           {"ports": sorted(http_ports)}))

    # surface d'attaque : beaucoup de ports ouverts
    if len(tcp) >= 15:
        out.append(finding(f"{base}surface", "info", f"Surface d'attaque étendue sur {label}",
                           f"{len(tcp)} ports TCP ouverts.",
                           "Ferme les services inutiles pour réduire l'exposition.", did,
                           {"open_ports": len(tcp)}))
    return out
