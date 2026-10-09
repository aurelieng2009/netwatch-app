"""Surveillance de Zigbee2MQTT : écoute le broker MQTT et journalise la disponibilité des
appareils, la qualité de lien (LQI), la batterie, les erreurs du pont et les événements du réseau.
L'analyse sur une période est dans z2mdiag.py ; l'import de l'historique Home Assistant dans
hahistory.py.

Topics lus (sous le topic de base, `zigbee2mqtt` par défaut) :
  bridge/state, bridge/info, bridge/devices, bridge/logging, bridge/event,
  bridge/response/networkmap, <appareil>/availability, <appareil> (état : linkquality, battery).
Le mot de passe MQTT et le jeton Home Assistant sont chiffrés par le coffre (vault.py) et ne
ressortent jamais par l'API.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time

from . import hahistory, mqttsub, z2mdiag
from .config import Config
from .db import DB
from .notify import mqtt_publish
from .vault import Vault, VaultError

log = logging.getLogger("netwatch.z2m")

META_MQTT_PASSWORD = "mqtt_password"
META_HA_TOKEN = "ha_token"
META_INFO = "z2m_info"
META_NETMAP = "z2m_networkmap"
META_BRIDGE = "z2m_bridge_state"
SAMPLE_EVERY = 300          # au plus un échantillon LQI/batterie par appareil et par 5 min
EVENT_KINDS = {"device_joined", "device_leave", "device_announce", "device_interview"}

_IEEE = re.compile(r"0x[0-9a-fA-F]{16}")
_QUOTED = re.compile(r"'([^']+)'")
_CATS = (
    ("interview", re.compile(r"interview", re.I)),
    ("route", re.compile(r"no route|route|NWK_|parent|address conflict", re.I)),
    ("delivery", re.compile(r"delivery failed|no ack|MAC_|timeout|timed out|failed to ping|failed to (?:send|call|read|write)|"
                            r"publish .* failed|not reachable|unreachable", re.I)),
)


# ------------------------------------------------------------------ analyse des messages
def parse_state(payload: bytes) -> bool | None:
    """`online`/`offline`, en texte brut (Z2M 1.x) ou `{"state": "online"}` (Z2M 2.x)."""
    txt = payload.decode("utf-8", "replace").strip()
    if txt.startswith("{"):
        try:
            txt = str(json.loads(txt).get("state", ""))
        except (ValueError, AttributeError):
            return None
    txt = txt.strip().strip('"').lower()
    return True if txt == "online" else False if txt == "offline" else None


MAX_DEVICES = 1000         # un réseau Zigbee n'en compte jamais autant : borne les charges forgées
LOG_PER_MINUTE = 60        # lignes de journal Zigbee2MQTT enregistrées par minute, au plus


def _txt(v, n: int) -> str | None:
    """Texte court ou rien : les messages MQTT viennent du réseau, on ne garde ni objets ni romans."""
    if v is None or isinstance(v, (dict, list)):
        return None
    return str(v)[:n]


def _number(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def parse_devices(payload: bytes) -> list[dict]:
    try:
        raw = json.loads(payload)
    except ValueError:
        return []
    out = []
    for d in (raw if isinstance(raw, list) else [])[:MAX_DEVICES]:
        if not isinstance(d, dict) or not d.get("ieee_address") or not d.get("friendly_name"):
            continue
        definition = d.get("definition") if isinstance(d.get("definition"), dict) else {}
        nwk = d.get("network_address")
        out.append({
            "ieee": _txt(d["ieee_address"], 40).lower(), "name": _txt(d["friendly_name"], 120),
            "type": _txt(d.get("type"), 20), "vendor": _txt(definition.get("vendor"), 80),
            "model": _txt(definition.get("model") or d.get("model_id"), 80),
            "power": _txt(d.get("power_source"), 40), "nwk": nwk if isinstance(nwk, int) else None,
            "disabled": bool(d.get("disabled")),
        })
    return out


def log_category(message: str) -> str:
    for cat, rx in _CATS:
        if rx.search(message):
            return cat
    return "other"


def parse_info(payload: bytes) -> dict | None:
    try:
        d = json.loads(payload)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    def sub(o, k):
        return o.get(k) if isinstance(o, dict) and isinstance(o.get(k), dict) else {}
    net, coord = sub(d, "network"), sub(d, "coordinator")
    meta = sub(coord, "meta")
    avail = sub(d, "config").get("availability")
    if isinstance(avail, dict):
        avail = avail.get("enabled", True)
    fw = meta.get("revision") or meta.get("version")
    return {
        "version": _txt(d.get("version"), 40), "channel": _number(net.get("channel")),
        "pan_id": _number(net.get("pan_id")),
        "coordinator": _txt(coord.get("type"), 60), "coordinator_ieee": _txt(coord.get("ieee_address"), 40),
        "coordinator_fw": fw if _number(fw) is not None else (_txt(fw, 40) if not isinstance(fw, bool) else None),
        "availability_enabled": bool(avail),
    }


def parse_networkmap(payload: bytes) -> dict | None:
    """Réponse `bridge/response/networkmap` (type raw) → nœuds et liens normalisés."""
    try:
        d = json.loads(payload)
    except ValueError:
        return None
    value = ((d.get("data") or {}).get("value")) if isinstance(d, dict) else None
    if not isinstance(value, dict) or d.get("status") not in (None, "ok"):
        return None
    nodes = [{"ieee": str(n.get("ieeeAddr", "")).lower(), "name": n.get("friendlyName"),
              "type": n.get("type"), "nwk": n.get("networkAddress")}
             for n in value.get("nodes") or [] if isinstance(n, dict)]
    links = []
    for lk in value.get("links") or []:
        if not isinstance(lk, dict):
            continue
        src = lk.get("sourceIeeeAddr") or (lk.get("source") or {}).get("ieeeAddr")
        dst = lk.get("targetIeeeAddr") or (lk.get("target") or {}).get("ieeeAddr")
        if src and dst:
            links.append({"src": str(src).lower(), "dst": str(dst).lower(),
                          "lqi": lk.get("lqi", lk.get("linkquality")),
                          "depth": lk.get("depth"), "rel": lk.get("relationship")})
    return {"nodes": nodes, "links": links}


class Z2MMonitor:
    def __init__(self, cfg: Config, db: DB, vault: Vault, emit):
        self.cfg, self.db, self.vault, self.emit = cfg, db, vault, emit
        self.sub: mqttsub.MQTTSubscriber | None = None
        self.names: dict[str, str] = {}        # nom convivial -> adresse IEEE
        self._msg_seen: dict[str, int] = {}     # ieee -> dernier message (mémoire)
        self._last_sample: dict[str, int] = {}
        self._pending: list[tuple[str, bool, int]] = []   # disponibilités reçues avant `bridge/devices`
        self._log_window: tuple[int, int] = (0, 0)        # (minute, lignes enregistrées dans cette minute)
        self.info: dict | None = None
        self._load()
        self._load_mqtt_password()

    # -- état initial
    def _load(self) -> None:
        self.names = {r["name"]: r["ieee"] for r in
                      self.db.q("SELECT ieee, name FROM z2m_devices WHERE present=1 AND type != 'Coordinator'")}
        raw = self.db.get_meta(META_INFO)
        self.info = json.loads(raw) if raw else None

    def _load_mqtt_password(self) -> None:
        """Le mot de passe enregistré depuis l'interface prime sur la variable d'environnement."""
        token = self.db.get_meta(META_MQTT_PASSWORD)
        if token and not self.vault.locked:
            try:
                self.cfg.mqtt_password = self.vault.decrypt(token)
            except VaultError as e:
                log.warning("Mot de passe MQTT indéchiffrable : %s", e)

    def base(self) -> str:
        return (self.cfg.z2m_topic or "zigbee2mqtt").strip().strip("/") or "zigbee2mqtt"

    # -- secrets
    def set_mqtt_password(self, password: str) -> None:
        password = (password or "").strip("\r\n")
        if not password or len(password) > 256:
            raise ValueError("mot de passe vide ou trop long")
        self.db.set_meta(META_MQTT_PASSWORD, self.vault.encrypt(password) or "")
        self.cfg.mqtt_password = password

    def clear_mqtt_password(self) -> None:
        self.db.x("DELETE FROM meta WHERE key=?", [META_MQTT_PASSWORD])
        self.cfg.mqtt_password = None

    def set_ha_token(self, token: str) -> None:
        token = (token or "").strip()
        if not token or len(token) > 4096:
            raise ValueError("jeton vide ou trop long")
        self.db.set_meta(META_HA_TOKEN, self.vault.encrypt(token) or "")

    def clear_ha_token(self) -> None:
        self.db.x("DELETE FROM meta WHERE key=?", [META_HA_TOKEN])

    def _ha_token(self) -> str | None:
        return self.vault.decrypt(self.db.get_meta(META_HA_TOKEN))

    # -- boucle d'écoute
    def _signature(self) -> tuple | None:
        c = self.cfg
        if not (c.z2m_enabled and c.mqtt_host):
            return None
        return (c.mqtt_host, int(c.mqtt_port), c.mqtt_user, c.mqtt_password, self.base())

    async def run(self) -> None:
        """Garde l'abonnement aligné sur les réglages (activation, broker, topic)."""
        while True:
            sig = self._signature()
            if sig is None:
                self.sub = None
                await asyncio.sleep(3)
                continue
            self.sub = mqttsub.MQTTSubscriber(self.cfg, [f"{self.base()}/#"], self.handle)
            task = asyncio.create_task(self.sub.run(), name="z2m-mqtt")
            try:
                while self._signature() == sig and not task.done():
                    await asyncio.sleep(2)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test(self) -> dict:
        """Essai de connexion : broker, identifiants, puis présence du pont Zigbee2MQTT."""
        if not self.cfg.mqtt_host:
            return {"ok": False, "error": "aucun broker MQTT configuré"}
        base = self.base()
        try:
            got = await mqttsub.probe(self.cfg, [f"{base}/bridge/state", f"{base}/bridge/devices"], wait=3.0)
        except mqttsub.MQTTError as e:
            return {"ok": False, "error": str(e)}
        state = parse_state(got.get(f"{base}/bridge/state", b""))
        devices = parse_devices(got.get(f"{base}/bridge/devices", b""))
        res = {"ok": True, "bridge": None if state is None else ("online" if state else "offline"),
               "devices": len([d for d in devices if d["type"] != "Coordinator"]) if devices else None}
        if state is None:
            res["warning"] = (f"Broker joignable, mais aucun message de Zigbee2MQTT sous « {base}/ » : "
                              "vérifiez le topic de base (base_topic) ou que Zigbee2MQTT est démarré.")
        return res

    # -- traitement des messages
    async def handle(self, topic: str, payload: bytes) -> None:
        base = self.base()
        if not topic.startswith(base + "/"):
            return
        rest = topic[len(base) + 1:]
        now = int(time.time())
        if rest == "bridge/state":
            await self._bridge_state(payload, now)
        elif rest == "bridge/info":
            self._bridge_info(payload)
        elif rest == "bridge/devices":
            self._bridge_devices(payload, now)
        elif rest == "bridge/logging":
            self._bridge_log(payload, now)
        elif rest == "bridge/event":
            self._bridge_event(payload, now)
        elif rest == "bridge/response/networkmap":
            self._networkmap(payload, now)
        elif rest.startswith("bridge/"):
            return
        elif rest.endswith("/availability"):
            self._availability(rest[:-len("/availability")], payload, now)
        else:
            self._device_state(rest, payload, now)

    async def _bridge_state(self, payload: bytes, now: int) -> None:
        online = parse_state(payload)
        if online is None:
            return
        prev = self.db.get_meta(META_BRIDGE)
        if prev is not None and prev == ("1" if online else "0"):
            return
        self.db.set_meta(META_BRIDGE, "1" if online else "0")
        self.db.x("INSERT INTO z2m_avail(ts, ieee, online, src) VALUES(?,?,?,?)",
                  [now, "bridge", int(online), "init" if prev is None else "mqtt"])
        if prev is None:
            return
        if online:
            await self.emit("z2m_bridge", "Zigbee2MQTT est de nouveau en ligne.", None, "info")
        else:
            await self.emit("z2m_bridge", "Zigbee2MQTT est hors ligne : tout le réseau Zigbee est injoignable.",
                            None, "critical")

    def _bridge_info(self, payload: bytes) -> None:
        info = parse_info(payload)
        if info:
            self.info = info
            self.db.set_meta(META_INFO, json.dumps(info))

    def _bridge_devices(self, payload: bytes, now: int) -> None:
        devices = parse_devices(payload)
        if not devices:
            return
        seen = set()
        for d in devices:
            seen.add(d["ieee"])
            self.db.x(
                "INSERT INTO z2m_devices(ieee, name, type, vendor, model, power, nwk, disabled, present, updated) "
                "VALUES(?,?,?,?,?,?,?,?,1,?) ON CONFLICT(ieee) DO UPDATE SET name=excluded.name, type=excluded.type, "
                "vendor=excluded.vendor, model=excluded.model, power=excluded.power, nwk=excluded.nwk, "
                "disabled=excluded.disabled, present=1, updated=excluded.updated",
                [d["ieee"], d["name"], d["type"], d["vendor"], d["model"], d["power"], d["nwk"],
                 int(d["disabled"]), now])
        for r in self.db.q("SELECT ieee FROM z2m_devices WHERE present=1"):
            if r["ieee"] not in seen:     # appareil retiré du réseau : on garde l'historique
                self.db.x("UPDATE z2m_devices SET present=0 WHERE ieee=?", [r["ieee"]])
        self._load()
        pending, self._pending = self._pending, []
        for name, online, ts in pending:
            self._availability(name, b"online" if online else b"offline", ts)

    def _availability(self, name: str, payload: bytes, now: int) -> None:
        online = parse_state(payload)
        if online is None:
            return
        ieee = self.names.get(name)
        if not ieee:
            if len(self._pending) < 500:
                self._pending.append((name, online, now))
            return
        row = self.db.q1("SELECT online FROM z2m_devices WHERE ieee=?", [ieee])
        prev = row["online"] if row else None
        if prev is not None and bool(prev) == online:
            return
        self.db.x("INSERT INTO z2m_avail(ts, ieee, online, src) VALUES(?,?,?,?)",
                  [now, ieee, int(online), "init" if prev is None else "mqtt"])
        self.db.x("UPDATE z2m_devices SET online=?, online_ts=? WHERE ieee=?", [int(online), now, ieee])

    def _device_state(self, name: str, payload: bytes, now: int) -> None:
        ieee = self.names.get(name)
        if not ieee:
            return
        self._msg_seen[ieee] = now
        if now - self._last_sample.get(ieee, 0) < SAMPLE_EVERY:
            return
        try:
            d = json.loads(payload)
        except ValueError:
            return
        if not isinstance(d, dict):
            return
        lqi, batt = d.get("linkquality"), d.get("battery")
        lqi = int(lqi) if isinstance(lqi, (int, float)) else None
        batt = int(batt) if isinstance(batt, (int, float)) else None
        self._last_sample[ieee] = now
        if lqi is not None or batt is not None:
            self.db.x("INSERT INTO z2m_samples(ts, ieee, lqi, battery) VALUES(?,?,?,?)", [now, ieee, lqi, batt])
        self.db.x("UPDATE z2m_devices SET last_msg=?, lqi=COALESCE(?, lqi), battery=COALESCE(?, battery) WHERE ieee=?",
                  [now, lqi, batt, ieee])

    def _log_allowed(self, now: int) -> bool:
        """Borne le journal : une rafale de messages ne doit pas remplir la base."""
        minute, n = self._log_window
        if minute != now // 60:
            minute, n = now // 60, 0
        self._log_window = (minute, n + 1)
        return n < LOG_PER_MINUTE

    def _guess_device(self, message: str) -> str | None:
        for q in _QUOTED.findall(message):
            if q in self.names:
                return self.names[q]
        m = _IEEE.search(message)
        return m.group(0).lower() if m else None

    def _bridge_log(self, payload: bytes, now: int) -> None:
        try:
            d = json.loads(payload)
            level, msg = str(d.get("level", "")), str(d.get("message", ""))
        except (ValueError, AttributeError):
            return
        if level not in ("warning", "error") or not msg or not self._log_allowed(now):
            return
        msg = msg[:300]
        self.db.x("INSERT INTO z2m_log(ts, kind, level, ieee, cat, message) VALUES(?,?,?,?,?,?)",
                  [now, "log", level, self._guess_device(msg), log_category(msg), msg])

    def _bridge_event(self, payload: bytes, now: int) -> None:
        try:
            d = json.loads(payload)
            kind = str(d.get("type", ""))
            data = d.get("data") or {}
        except (ValueError, AttributeError):
            return
        if kind not in EVENT_KINDS or not isinstance(data, dict) or not self._log_allowed(now):
            return
        ieee = str(data.get("ieee_address") or "").lower() or self.names.get(str(data.get("friendly_name")))
        status = data.get("status")
        name = data.get("friendly_name") or ieee or "?"
        self.db.x("INSERT INTO z2m_log(ts, kind, level, ieee, cat, message) VALUES(?,?,?,?,?,?)",
                  [now, kind, "warning" if kind == "device_leave" else "info", ieee or None,
                   "interview" if kind == "device_interview" else "other",
                   f"{name}{' : ' + str(status) if status else ''}"[:300]])

    def _networkmap(self, payload: bytes, now: int) -> None:
        nm = parse_networkmap(payload)
        if nm:
            nm["ts"] = now
            self.db.set_meta(META_NETMAP, json.dumps(nm))

    # -- actions
    async def request_networkmap(self) -> None:
        """Demande la carte du réseau (génère du trafic Zigbee : à déclencher à la main)."""
        if not (self.sub and self.sub.connected):
            raise mqttsub.MQTTError("non connecté à Zigbee2MQTT")
        msg = [(f"{self.base()}/bridge/request/networkmap", json.dumps({"type": "raw", "routes": False}), False)]
        try:
            await asyncio.to_thread(mqtt_publish, self.cfg, msg, "netwatch-z2m-req")
        except OSError as e:
            raise mqttsub.MQTTError(f"publication impossible ({e})") from e

    async def import_ha(self, hours: int) -> dict:
        if self.vault.locked:
            raise hahistory.HAError("coffre verrouillé : " + (self.vault.reason or ""))
        try:
            token = self._ha_token()
        except VaultError as e:
            raise hahistory.HAError(str(e)) from e
        if not token:
            raise hahistory.HAError("aucun jeton Home Assistant enregistré")
        return await asyncio.to_thread(hahistory.import_history, self.db, self.cfg.ha_url, token, hours,
                                     bool(self.cfg.ha_verify_tls))

    # -- restitution
    def status(self) -> dict:
        c = self.cfg
        devs = self.db.q("SELECT online FROM z2m_devices WHERE present=1 AND disabled=0 AND type != 'Coordinator'")
        bridge = self.db.get_meta(META_BRIDGE)
        nm = self.db.get_meta(META_NETMAP)
        sub = self.sub
        return {
            "enabled": bool(c.z2m_enabled), "topic": self.base(),
            "mqtt_configured": bool(c.mqtt_host), "host": c.mqtt_host or "", "port": c.mqtt_port,
            "user": c.mqtt_user or "",
            "has_password": bool(c.mqtt_password), "vault_locked": self.vault.locked,
            "connected": bool(sub and sub.connected), "error": sub.error if sub else None,
            "since": sub.since if sub else None, "last_message": sub.last_message if sub else None,
            "messages": sub.messages if sub else 0,
            "bridge": None if bridge is None else bridge == "1", "info": self.info,
            "devices": len(devs), "online": sum(1 for d in devs if d["online"] == 1),
            "offline": sum(1 for d in devs if d["online"] == 0),
            "availability_seen": bool(self.db.q1("SELECT 1 FROM z2m_avail WHERE ieee != 'bridge' LIMIT 1")),
            "ha": {"url": c.ha_url, "url_allowed": hahistory.url_allowed(c.ha_url) if c.ha_url else None,
                   "has_token": bool(self.db.get_meta(META_HA_TOKEN)), "verify_tls": bool(c.ha_verify_tls)},
            "networkmap_ts": json.loads(nm)["ts"] if nm else None,
        }

    def report(self, hours: int) -> dict:
        now = int(time.time())
        nm = self.db.get_meta(META_NETMAP)
        return z2mdiag.build_report(self.db, now - hours * 3600, now, self.info,
                                    json.loads(nm) if nm else None)
