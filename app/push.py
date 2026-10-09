"""Notifications Web Push (VAPID). Chaque appareil (navigateur/PWA) s'abonne et choisit
les types d'alerte qu'il veut recevoir. Les clés VAPID sont générées une fois et gardées
en base. L'envoi (bloquant, via pywebpush) est appelé depuis un thread par le notifieur.

Les fonctions de sélection et de construction du message sont pures (testables sans réseau).
"""
from __future__ import annotations

import base64
import json
import logging
import time

log = logging.getLogger("netwatch.push")

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from py_vapid import Vapid01
    from pywebpush import WebPushException, webpush
    _AVAILABLE = True
except ImportError:  # pragma: no cover
    _AVAILABLE = False
    WebPushException = Exception  # type: ignore[assignment,misc]

# Types d'alerte proposés à l'abonnement : (clé, libellé, activé par défaut)
EVENT_TYPES = [
    ("new_device", "Nouvel appareil", True),
    ("device_offline", "Appareil hors ligne", True),
    ("device_online", "Appareil de retour", False),
    ("ip_conflict", "Conflit d'adresse IP", True),
    ("latency_anomaly", "Latence suspecte", True),
    ("high_latency", "Latence élevée", True),
    ("diag_finding", "Diagnostic de latence", True),
    ("ssh_hostkey_changed", "Clé SSH modifiée", True),
    ("security_finding", "Alerte de sécurité", True),
    ("rogue_dhcp", "DHCP pirate détecté", True),
    ("gateway_mac_changed", "MAC passerelle modifiée", True),
    ("bbox_reboot", "Redémarrage de la box", True),
    ("bbox_internet", "Internet coupé (box)", True),
    ("bbox_auth", "Box : identifiants refusés", True),
    ("bbox_firmware", "Firmware de la box mis à jour", False),
    ("wifi_channel", "Canal Wi-Fi modifié (radar, optimisation)", False),
    ("port_opened", "Nouveau port ouvert", True),
    ("port_closed", "Port fermé", False),
    ("ip_changed", "Changement d'IP", False),
    ("latency_ok", "Retour à la normale", False),
]
DEFAULT_TYPES = [k for k, _, on in EVENT_TYPES if on]
VALID_TYPES = {k for k, _, _ in EVENT_TYPES}
TITLES = {
    "new_device": "Nouvel appareil", "device_offline": "Appareil hors ligne",
    "device_online": "Appareil de retour", "ip_conflict": "Conflit d'IP",
    "latency_anomaly": "Latence suspecte", "high_latency": "Latence élevée",
    "diag_finding": "Diagnostic", "ssh_hostkey_changed": "Clé SSH modifiée",
    "security_finding": "Sécurité", "rogue_dhcp": "DHCP pirate",
    "gateway_mac_changed": "MAC passerelle modifiée",
    "bbox_reboot": "Box redémarrée", "bbox_internet": "Internet (box)",
    "bbox_auth": "Box : accès refusé", "bbox_firmware": "Firmware de la box",
    "wifi_channel": "Canal Wi-Fi modifié",
    "port_opened": "Nouveau port ouvert", "port_closed": "Port fermé",
    "ip_changed": "Changement d'IP", "latency_ok": "Retour à la normale",
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sanitize_types(types) -> list[str]:
    """Garde uniquement des types connus ; défaut si rien de valide."""
    if not isinstance(types, list):
        return list(DEFAULT_TYPES)
    out = [t for t in types if t in VALID_TYPES]
    return out


def build_payload(ev: dict, device: dict | None) -> dict:
    """Construit le message push à partir d'un événement (fonction pure)."""
    title = "NetWatch · " + TITLES.get(ev["type"], ev["type"])
    url = f"/#/device/{device['id']}" if device and device.get("id") else "/#/events"
    return {
        "title": title,
        "body": ev.get("message", ""),
        "tag": ev["type"] + (f":{device['id']}" if device and device.get("id") else ""),
        "url": url,
        "severity": ev.get("severity", "info"),
    }


def ua_label(ua: str | None) -> str:
    if not ua:
        return "Appareil"
    u = ua.lower()
    for needle, name in (("android", "Android"), ("iphone", "iPhone"), ("ipad", "iPad"),
                         ("macintosh", "Mac"), ("windows", "Windows"), ("linux", "Linux")):
        if needle in u:
            browser = "Chrome" if "chrome" in u and "edg" not in u else \
                      "Edge" if "edg" in u else "Firefox" if "firefox" in u else \
                      "Safari" if "safari" in u else ""
            return f"{name}{(' · ' + browser) if browser else ''}"
    return "Appareil"


def endpoint_allowed(endpoint: str) -> bool:
    """Un service push est une URL HTTPS publique : jamais une adresse du réseau local (sinon le
    serveur enverrait des requêtes là où on le lui demande)."""
    import ipaddress
    import urllib.parse
    try:
        p = urllib.parse.urlparse(str(endpoint))
        host = (p.hostname or "").lower()
    except ValueError:
        return False
    if p.scheme != "https" or not host or p.username or p.password or len(str(endpoint)) > 1000:
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return "." in host and not host.endswith((".local", ".lan", ".home", ".internal", ".localhost"))


class PushManager:
    def __init__(self, cfg, db, vault=None):
        self.cfg = cfg
        self.db = db
        self.vault = vault
        self._pem: str | None = None
        self._app_key: str | None = None
        self._vapid = None
        if _AVAILABLE:
            self._load_keys()

    @property
    def available(self) -> bool:
        return _AVAILABLE and bool(self._app_key)

    def _load_keys(self) -> None:
        # la clé privée VAPID est chiffrée par le coffre ; l'ancien stockage en clair est migré puis effacé
        usable = self.vault is not None and not self.vault.locked
        pem = None
        enc = self.db.get_meta("vapid_private_enc")
        if enc and usable:
            try:
                pem = self.vault.decrypt(enc)
            except Exception:  # noqa: BLE001
                pem = None
        if not pem:
            pem = self.db.get_meta("vapid_private_pem")
        if not pem:
            priv = ec.generate_private_key(ec.SECP256R1())
            pem = priv.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).decode()
            if not usable:
                self.db.set_meta("vapid_private_pem", pem)
            log.info("Clés VAPID générées pour les notifications push.")
        if usable and not (enc and self.db.get_meta("vapid_private_pem") is None):
            self.db.set_meta("vapid_private_enc", self.vault.encrypt(pem))
            self.db.x("DELETE FROM meta WHERE key='vapid_private_pem'")
        priv = serialization.load_pem_private_key(pem.encode(), password=None)
        raw = priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self._pem = pem
        self._app_key = _b64url(raw)
        # pywebpush ne sait pas lire un PEM PKCS8 en chaîne : on lui passe un objet Vapid
        self._vapid = Vapid01.from_pem(pem.encode())

    @property
    def application_server_key(self) -> str | None:
        return self._app_key

    # -------------------------------------------------------------- abonnements
    def subscribe(self, sub: dict, notify_types, ua: str | None) -> dict:
        endpoint = sub.get("endpoint")
        keys = sub.get("keys") or {}
        if not endpoint or not keys.get("p256dh") or not keys.get("auth"):
            raise ValueError("abonnement push invalide")
        if not endpoint_allowed(endpoint) or len(str(keys["p256dh"])) > 200 or len(str(keys["auth"])) > 100:
            raise ValueError("adresse de notification refusée (service push HTTPS public attendu)")
        if self.db.q1("SELECT COUNT(*) AS n FROM push_subscriptions")["n"] >= 50 and not self.get(endpoint):
            raise ValueError("trop d'appareils abonnés")
        types = json.dumps(sanitize_types(notify_types))
        now = int(time.time())
        self.db.x(
            """INSERT INTO push_subscriptions(endpoint, p256dh, auth, notify_types, label, created)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(endpoint) DO UPDATE SET
                 p256dh=excluded.p256dh, auth=excluded.auth, notify_types=excluded.notify_types,
                 label=excluded.label, enabled=1, fail_count=0, last_error=NULL""",
            [endpoint, keys["p256dh"], keys["auth"], types, ua_label(ua), now])
        return self.get(endpoint)

    def get(self, endpoint: str) -> dict | None:
        r = self.db.q1("SELECT * FROM push_subscriptions WHERE endpoint=?", [endpoint])
        return self.public(r) if r else None

    def list(self) -> list[dict]:
        return [self.public(r) for r in self.db.q("SELECT * FROM push_subscriptions ORDER BY id")]

    @staticmethod
    def public(r: dict) -> dict:
        return {
            "id": r["id"], "label": r["label"], "enabled": bool(r["enabled"]),
            "notify_types": json.loads(r["notify_types"] or "[]"),
            "created": r["created"], "last_ok": r["last_ok"],
            "last_error": r["last_error"], "endpoint_tail": (r["endpoint"] or "")[-12:],
        }

    def update(self, endpoint: str, notify_types=None, enabled=None) -> dict | None:
        if not self.db.q1("SELECT id FROM push_subscriptions WHERE endpoint=?", [endpoint]):
            return None
        fields: dict = {}
        if notify_types is not None:
            fields["notify_types"] = json.dumps(sanitize_types(notify_types))
        if enabled is not None:
            fields["enabled"] = int(bool(enabled))
        if fields:
            self.db.update2("push_subscriptions", "endpoint", endpoint, fields)
        return self.get(endpoint)

    def unsubscribe(self, endpoint: str) -> None:
        self.db.x("DELETE FROM push_subscriptions WHERE endpoint=?", [endpoint])

    def unsubscribe_tail(self, tail: str) -> None:
        """Supprime par les derniers caractères de l'endpoint (pour retirer un autre appareil)."""
        tail = str(tail or "")
        if len(tail) >= 8:
            for r in self.db.q("SELECT endpoint FROM push_subscriptions"):
                if r["endpoint"].endswith(tail):
                    self.unsubscribe(r["endpoint"])

    # -------------------------------------------------------------- envoi (bloquant)
    def _send_one(self, row: dict, payload: dict) -> None:
        sub = {"endpoint": row["endpoint"], "keys": {"p256dh": row["p256dh"], "auth": row["auth"]}}
        try:
            webpush(sub, json.dumps(payload), vapid_private_key=self._vapid,
                    vapid_claims={"sub": self.cfg.vapid_subject}, ttl=600)
            self.db.update2("push_subscriptions", "endpoint", row["endpoint"],
                            {"last_ok": int(time.time()), "fail_count": 0, "last_error": None})
        except WebPushException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in (404, 410):  # abonnement expiré/supprimé côté navigateur
                self.unsubscribe(row["endpoint"])
                log.info("Abonnement push expiré, supprimé (%s)", row["endpoint"][-12:])
            else:
                self.db.update2("push_subscriptions", "endpoint", row["endpoint"],
                                {"fail_count": row["fail_count"] + 1, "last_error": str(e)[:200]})
                log.warning("Envoi push en échec (%s): %s", row["endpoint"][-12:], e)
        except Exception as e:  # noqa: BLE001 - jamais laisser remonter (sinon 500 côté API)
            self.db.update2("push_subscriptions", "endpoint", row["endpoint"],
                            {"fail_count": row["fail_count"] + 1, "last_error": str(e)[:200]})
            log.warning("Envoi push : erreur inattendue (%s): %s", row["endpoint"][-12:], e)

    def send_event(self, ev: dict, device: dict | None) -> int:
        """Envoie l'événement à tous les abonnements qui ont souscrit à ce type. Bloquant."""
        if not self.available:
            return 0
        payload = build_payload(ev, device)
        sent = 0
        for row in self.db.q("SELECT * FROM push_subscriptions WHERE enabled=1"):
            if ev["type"] in json.loads(row["notify_types"] or "[]"):
                self._send_one(row, payload)
                sent += 1
        return sent

    def send_test(self, endpoint: str) -> bool:
        row = self.db.q1("SELECT * FROM push_subscriptions WHERE endpoint=?", [endpoint])
        if not row or not self.available:
            return False
        self._send_one(row, {
            "title": "NetWatch · Test", "body": "Les notifications fonctionnent 🎉",
            "tag": "test", "url": "/#/notifications", "severity": "info"})
        return True
