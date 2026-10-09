"""Configuration via variables d'environnement (préfixe NETWATCH_)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(f"NETWATCH_{name}", default)


def _int(name: str, default: int) -> int:
    v = _env(name)
    return int(v) if v not in (None, "") else default


def _float(name: str, default: float) -> float:
    v = _env(name)
    return float(v) if v not in (None, "") else default


def _bool(name: str, default: bool) -> bool:
    v = _env(name)
    if v in (None, ""):
        return default
    return v.strip().lower() in ("1", "true", "yes", "on", "oui")


def _list(name: str, default: str) -> list[str]:
    v = _env(name, default) or ""
    return [x.strip() for x in v.split(",") if x.strip()]


@dataclass
class Config:
    # Réseau
    interface: str | None = field(default_factory=lambda: _env("INTERFACE"))
    subnet: str | None = field(default_factory=lambda: _env("SUBNET"))  # ex. 192.168.1.0/24
    external_targets: list[str] = field(
        default_factory=lambda: _list("EXTERNAL_TARGETS", "1.1.1.1,8.8.8.8")
    )
    # Hôtes à ne jamais scanner (ni ARP, ni ping, ni nmap, ni SSH) : IP ou CIDR
    exclude: list[str] = field(default_factory=lambda: _list("EXCLUDE", ""))

    # Interrupteur général des scans automatiques (découverte, nmap, nouveaux appareils)
    scans_enabled: bool = field(default_factory=lambda: _bool("SCANS_ENABLED", True))

    # Cadences (secondes)
    discovery_interval: int = field(default_factory=lambda: _int("DISCOVERY_INTERVAL", 60))
    deep_interval: int = field(default_factory=lambda: _int("DEEP_INTERVAL", 3600))
    name_refresh_interval: int = field(default_factory=lambda: _int("NAME_REFRESH_INTERVAL", 1800))

    # Découverte
    ping_count: int = field(default_factory=lambda: _int("PING_COUNT", 3))
    ping_timeout: float = field(default_factory=lambda: _float("PING_TIMEOUT", 1.0))
    arp_timeout: float = field(default_factory=lambda: _float("ARP_TIMEOUT", 2.0))
    arp_retries: int = field(default_factory=lambda: _int("ARP_RETRIES", 2))
    offline_after: int = field(default_factory=lambda: _int("OFFLINE_AFTER", 3))  # cycles manqués

    # Scan approfondi (nmap)
    deep_enabled: bool = field(default_factory=lambda: _bool("DEEP_ENABLED", True))
    nmap_args: str = field(
        default_factory=lambda: _env(
            "NMAP_ARGS",
            "-sS -sV --version-light -O --osscan-limit --top-ports 1000 -T4 --host-timeout 300s",
        )
    )
    nmap_concurrency: int = field(default_factory=lambda: _int("NMAP_CONCURRENCY", 3))

    # Inventaire SSH authentifié
    ssh_enabled: bool = field(default_factory=lambda: _bool("SSH_ENABLED", True))
    # un mot de passe SSH n'est présenté qu'aux appareils approuvés (une clé, elle, ne fuit pas)
    ssh_known_only: bool = field(default_factory=lambda: _bool("SSH_KNOWN_ONLY", True))
    ssh_timeout: float = field(default_factory=lambda: _float("SSH_TIMEOUT", 10.0))
    ssh_command_timeout: float = field(default_factory=lambda: _float("SSH_COMMAND_TIMEOUT", 60.0))
    # nombre max de jeux d'identifiants essayés par hôte et par cycle (évite fail2ban)
    ssh_max_attempts: int = field(default_factory=lambda: _int("SSH_MAX_ATTEMPTS", 3))
    # un couple (identifiant, hôte) refusé n'est pas réessayé avant ce délai (s)
    ssh_retry_after: int = field(default_factory=lambda: _int("SSH_RETRY_AFTER", 86400))
    # clé maître des identifiants ; à défaut, clé générée dans DATA_DIR/secret.key
    secret_key: str | None = field(default_factory=lambda: _env("SECRET_KEY"))

    # Box Internet (Bouygues, Free, Orange, SFR) via son API locale ; hôte vide = passerelle détectée.
    # Les anciens noms NETWATCH_BBOX_* restent acceptés.
    box_enabled: bool = field(default_factory=lambda: _bool("BOX_ENABLED", _bool("BBOX_ENABLED", False)))
    box_host: str = field(default_factory=lambda: _env("BOX_HOST", _env("BBOX_HOST", "")) or "")
    box_interval: int = field(default_factory=lambda: _int("BOX_INTERVAL", _int("BBOX_INTERVAL", 60)))
    # suivi des sessions Wi-Fi (coupures, itinérance) à partir de la liste d'appareils de la box
    wifi_tracking: bool = field(default_factory=lambda: _bool("WIFI_TRACKING", True))

    # Diagnostic de latence
    diag_enabled: bool = field(default_factory=lambda: _bool("DIAG_ENABLED", True))
    diag_interval: int = field(default_factory=lambda: _int("DIAG_INTERVAL", 3600))
    diag_ping_count: int = field(default_factory=lambda: _int("DIAG_PING_COUNT", 20))
    diag_dns_domain: str = field(default_factory=lambda: _env("DIAG_DNS_DOMAIN", "example.com"))
    diag_dns_servers: list[str] = field(default_factory=lambda: _list("DIAG_DNS_SERVERS", "1.1.1.1,8.8.8.8"))
    diag_tcp_targets: list[str] = field(
        default_factory=lambda: _list("DIAG_TCP_TARGETS", "1.1.1.1:443,8.8.8.8:443")
    )
    # test de bufferbloat : télécharge ce fichier en mesurant la latence (vide = désactivé)
    bufferbloat_url: str | None = field(default_factory=lambda: _env("BUFFERBLOAT_URL"))
    bufferbloat_seconds: float = field(default_factory=lambda: _float("BUFFERBLOAT_SECONDS", 8.0))
    # anomalie : latence 15 min > max(référence × facteur, référence + marge)
    anomaly_factor: float = field(default_factory=lambda: _float("ANOMALY_FACTOR", 3.0))
    anomaly_margin_ms: float = field(default_factory=lambda: _float("ANOMALY_MARGIN_MS", 15.0))
    # délai minimal entre deux diagnostics ciblés déclenchés par une anomalie (s)
    diag_trigger_cooldown: int = field(default_factory=lambda: _int("DIAG_TRIGGER_COOLDOWN", 600))

    # Conflits d'IP : fenêtre pendant laquelle deux MAC sur la même IP sont un conflit (s)
    conflict_window: int = field(default_factory=lambda: _int("CONFLICT_WINDOW", 900))

    # Alertes
    latency_warn_ms: float = field(default_factory=lambda: _float("LATENCY_WARN_MS", 100.0))
    external_latency_warn_ms: float = field(
        default_factory=lambda: _float("EXTERNAL_LATENCY_WARN_MS", 80.0)
    )
    loss_warn_pct: float = field(default_factory=lambda: _float("LOSS_WARN_PCT", 50.0))

    # Notifications
    ntfy_url: str | None = field(default_factory=lambda: _env("NTFY_URL"))  # ex. https://ntfy.sh/mon-topic
    ntfy_token: str | None = field(default_factory=lambda: _env("NTFY_TOKEN"))
    mqtt_host: str | None = field(default_factory=lambda: _env("MQTT_HOST"))
    mqtt_port: int = field(default_factory=lambda: _int("MQTT_PORT", 1883))
    mqtt_user: str | None = field(default_factory=lambda: _env("MQTT_USER"))
    mqtt_password: str | None = field(default_factory=lambda: _env("MQTT_PASSWORD"))
    mqtt_prefix: str = field(default_factory=lambda: _env("MQTT_PREFIX", "netwatch"))
    mqtt_discovery: bool = field(default_factory=lambda: _bool("MQTT_DISCOVERY", True))
    mqtt_discovery_prefix: str = field(default_factory=lambda: _env("MQTT_DISCOVERY_PREFIX", "homeassistant"))
    notify_types: list[str] = field(
        default_factory=lambda: _list(
            "NOTIFY_TYPES",
            "new_device,device_offline,device_online,port_opened,high_latency,"
            "ip_conflict,gateway_mac_changed,ssh_hostkey_changed,latency_anomaly,diag_finding,"
            "security_finding,rogue_dhcp,bbox_reboot,bbox_internet,bbox_auth,z2m_bridge",
        )
    )

    # Zigbee2MQTT : écoute du broker MQTT ci-dessus (topic de base du pont)
    z2m_enabled: bool = field(default_factory=lambda: _bool("Z2M_ENABLED", False))
    z2m_topic: str = field(default_factory=lambda: _env("Z2M_TOPIC", "zigbee2mqtt") or "zigbee2mqtt")
    # Home Assistant (API REST) : import de l'historique de disponibilité ; le jeton est dans le coffre
    ha_url: str = field(default_factory=lambda: _env("HA_URL", "") or "")
    # false = accepte le certificat auto-signé de Home Assistant (l'URL reste limitée au réseau local)
    ha_verify_tls: bool = field(default_factory=lambda: _bool("HA_VERIFY_TLS", True))

    # Rétention
    raw_retention_days: int = field(default_factory=lambda: _int("RAW_RETENTION_DAYS", 14))
    hourly_retention_days: int = field(default_factory=lambda: _int("HOURLY_RETENTION_DAYS", 400))
    event_retention_days: int = field(default_factory=lambda: _int("EVENT_RETENTION_DAYS", 180))

    # Web
    host: str = field(default_factory=lambda: _env("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _int("PORT", 8484))
    username: str = field(default_factory=lambda: _env("USERNAME", "admin"))
    password: str | None = field(default_factory=lambda: _env("PASSWORD"))
    password_reset: bool = field(default_factory=lambda: _bool("PASSWORD_RESET", False))
    # true = interface ouverte sans authentification (comportement V1) ; sinon, si aucun mot de
    # passe n'est défini, un écran de configuration le demande au premier accès.
    no_auth: bool = field(default_factory=lambda: _bool("NO_AUTH", False))
    session_days: int = field(default_factory=lambda: _int("SESSION_DAYS", 30))
    # Proxys inverses de confiance (IP ou CIDR) : seul leur en-tête X-Forwarded-For est cru pour
    # connaître l'adresse du visiteur (limitation des tentatives de connexion).
    trusted_proxies: list[str] = field(default_factory=lambda: _list("TRUSTED_PROXIES", "127.0.0.1,::1"))
    # Sites autorisés à afficher NetWatch dans un cadre (iframe), ex. "https://ha.exemple.fr". Vide = aucun.
    frame_ancestors: str = field(default_factory=lambda: _env("FRAME_ANCESTORS", "") or "")
    # cookie Secure : "auto" (selon le schéma de la requête), "true" ou "false"
    session_cookie_secure: str = field(default_factory=lambda: _env("SESSION_COOKIE_SECURE", "auto"))
    # Web Push (VAPID) : sujet du jeton (mailto: ou URL du site)
    vapid_subject: str = field(default_factory=lambda: _env("VAPID_SUBJECT", "mailto:netwatch@localhost"))
    # WebAuthn (biométrie) : domaine et origine, déduits de la requête si vides
    rp_id: str | None = field(default_factory=lambda: _env("RP_ID"))
    rp_origin: str | None = field(default_factory=lambda: _env("RP_ORIGIN"))

    # Divers
    data_dir: str = field(default_factory=lambda: _env("DATA_DIR", "/data"))
    demo: bool = field(default_factory=lambda: _bool("DEMO", False))
    log_level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO"))

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "netwatch.db")

    @property
    def secret_key_path(self) -> str:
        return os.path.join(self.data_dir, "secret.key")


config = Config()
