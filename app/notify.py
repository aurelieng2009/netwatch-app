"""Notifications : ntfy (HTTP) et MQTT (client minimal 3.1.1, QoS 0, sans dépendance)."""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import struct
import urllib.request

from .config import Config

log = logging.getLogger("netwatch.notify")

PRIORITY = {"info": "default", "warning": "high", "critical": "urgent"}
TITLES = {
    "new_device": "Nouvel appareil",
    "device_offline": "Appareil hors ligne",
    "device_online": "Appareil de retour",
    "port_opened": "Nouveau port ouvert",
    "port_closed": "Port fermé",
    "high_latency": "Latence élevée",
    "latency_ok": "Latence revenue à la normale",
    "ip_changed": "Changement d'IP",
}


# ------------------------------------------------------------------ MQTT
def _mqtt_str(s: str) -> bytes:
    b = s.encode()
    return struct.pack("!H", len(b)) + b


def _remaining_length(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n:
            byte |= 0x80
        out.append(byte)
        if not n:
            return bytes(out)


def mqtt_connect_packet(client_id: str, user: str | None, password: str | None) -> bytes:
    flags = 0x02  # clean session
    payload = _mqtt_str(client_id)
    if user:
        flags |= 0x80
        payload += _mqtt_str(user)
        if password:
            flags |= 0x40
            payload += _mqtt_str(password)
    var = _mqtt_str("MQTT") + bytes([4, flags]) + struct.pack("!H", 30)
    body = var + payload
    return bytes([0x10]) + _remaining_length(len(body)) + body


def mqtt_publish_packet(topic: str, payload: bytes, retain: bool = False) -> bytes:
    body = _mqtt_str(topic) + payload
    return bytes([0x30 | (0x01 if retain else 0)]) + _remaining_length(len(body)) + body


def mqtt_publish(cfg: Config, messages: list[tuple[str, str, bool]], client_id: str = "netwatch") -> None:
    """Publie une liste de (topic, payload, retain) dans une seule connexion (bloquant)."""
    with socket.create_connection((cfg.mqtt_host, cfg.mqtt_port), timeout=5) as s:
        s.sendall(mqtt_connect_packet(client_id, cfg.mqtt_user, cfg.mqtt_password))
        ack = s.recv(4)
        if len(ack) < 4 or ack[0] != 0x20 or ack[3] != 0:
            raise ConnectionError(f"CONNACK refusé ({ack!r})")
        for topic, payload, retain in messages:
            s.sendall(mqtt_publish_packet(topic, payload.encode(), retain))
        s.sendall(b"\xe0\x00")  # DISCONNECT


# ------------------------------------------------------------------ ntfy
def ntfy_send(cfg: Config, title: str, message: str, priority: str, tags: str) -> None:
    req = urllib.request.Request(cfg.ntfy_url, data=message.encode(), method="POST")
    req.add_header("Title", title.encode("utf-8").decode("latin-1", "replace"))
    req.add_header("Priority", priority)
    req.add_header("Tags", tags)
    if cfg.ntfy_token:
        req.add_header("Authorization", f"Bearer {cfg.ntfy_token}")
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


class Notifier:
    def __init__(self, cfg: Config, push=None):
        self.cfg = cfg
        self.push = push  # PushManager | None

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.ntfy_url or self.cfg.mqtt_host or (self.push and self.push.available))

    async def event(self, ev: dict, device: dict | None) -> None:
        loop = asyncio.get_running_loop()
        # Web Push : chaque abonnement a son propre filtre par type (indépendant de NOTIFY_TYPES)
        if self.push and self.push.available:
            try:
                await loop.run_in_executor(None, self.push.send_event, ev, device)
            except Exception as e:  # noqa: BLE001
                log.warning("push: %s", e)
        if ev["type"] not in self.cfg.notify_types:
            return
        title = TITLES.get(ev["type"], ev["type"])
        tags = {"info": "information_source", "warning": "warning", "critical": "rotating_light"}.get(
            ev["severity"], "bell"
        )
        if self.cfg.ntfy_url:
            try:
                await loop.run_in_executor(
                    None, ntfy_send, self.cfg, f"NetWatch · {title}", ev["message"],
                    PRIORITY.get(ev["severity"], "default"), tags,
                )
            except Exception as e:  # noqa: BLE001
                log.warning("ntfy: %s", e)
        if self.cfg.mqtt_host:
            payload = json.dumps({**ev, "title": title, "device": _dev_summary(device)}, default=str)
            try:
                await loop.run_in_executor(
                    None, mqtt_publish, self.cfg, [(f"{self.cfg.mqtt_prefix}/events", payload, False)]
                )
            except Exception as e:  # noqa: BLE001
                log.warning("mqtt: %s", e)

    # ------------------------------------------------------------ Home Assistant (MQTT discovery)
    def ha_config_messages(self, d: dict) -> list[tuple[str, str, bool]]:
        """Messages de configuration MQTT Discovery pour un appareil (retain)."""
        macid = d["mac"].replace(":", "")
        state_topic = f"{self.cfg.mqtt_prefix}/device/{macid}/state"
        dev = {
            "identifiers": [f"netwatch_{macid}"],
            "name": d.get("alias") or d.get("hostname") or d.get("ip") or macid,
            "manufacturer": d.get("vendor") or None,
            "model": d.get("os_name") or None,
        }
        origin = {"name": "NetWatch"}
        pfx = self.cfg.mqtt_discovery_prefix
        conn = {
            "name": "En ligne", "unique_id": f"netwatch_{macid}_online", "object_id": f"{dev['name']}_online",
            "state_topic": state_topic, "value_template": "{{ 'ON' if value_json.online else 'OFF' }}",
            "device_class": "connectivity", "device": dev, "origin": origin,
        }
        lat = {
            "name": "Latence", "unique_id": f"netwatch_{macid}_latency", "object_id": f"{dev['name']}_latency",
            "state_topic": state_topic, "value_template": "{{ value_json.latency_ms | round(2) }}",
            "unit_of_measurement": "ms", "state_class": "measurement", "icon": "mdi:speedometer",
            "device": dev, "origin": origin,
        }
        return [
            (f"{pfx}/binary_sensor/netwatch_{macid}/config", json.dumps(conn), True),
            (f"{pfx}/sensor/netwatch_{macid}_lat/config", json.dumps(lat), True),
        ]

    async def ha_discovery(self, devices: list[dict]) -> None:
        if not (self.cfg.mqtt_host and self.cfg.mqtt_discovery) or not devices:
            return
        msgs: list[tuple[str, str, bool]] = []
        for d in devices:
            msgs += self.ha_config_messages(d)
        try:
            await asyncio.get_running_loop().run_in_executor(None, mqtt_publish, self.cfg, msgs)
            log.info("Home Assistant : %d appareil(s) publié(s) en découverte MQTT", len(devices))
        except Exception as e:  # noqa: BLE001
            log.warning("mqtt discovery: %s", e)

    async def ha_remove(self, macids: list[str]) -> None:
        """Supprime les entités HA (payload vide retenu) pour les appareils qu'on ne surveille plus."""
        if not (self.cfg.mqtt_host and self.cfg.mqtt_discovery) or not macids:
            return
        pfx = self.cfg.mqtt_discovery_prefix
        msgs = []
        for macid in macids:
            msgs.append((f"{pfx}/binary_sensor/netwatch_{macid}/config", "", True))
            msgs.append((f"{pfx}/sensor/netwatch_{macid}_lat/config", "", True))
        try:
            await asyncio.get_running_loop().run_in_executor(None, mqtt_publish, self.cfg, msgs)
        except Exception as e:  # noqa: BLE001
            log.warning("mqtt discovery remove: %s", e)

    async def device_states(self, devices: list[dict]) -> None:
        """Publie l'état retenu (retain) de chaque appareil : netwatch/device/<mac>/state."""
        if not self.cfg.mqtt_host:
            return
        msgs = []
        for d in devices:
            topic = f"{self.cfg.mqtt_prefix}/device/{d['mac'].replace(':', '')}/state"
            msgs.append((topic, json.dumps(_dev_summary(d)), True))
        try:
            await asyncio.get_running_loop().run_in_executor(None, mqtt_publish, self.cfg, msgs)
        except Exception as e:  # noqa: BLE001
            log.warning("mqtt: %s", e)


def _dev_summary(d: dict | None) -> dict | None:
    if not d:
        return None
    return {
        "id": d.get("id"),
        "name": d.get("alias") or d.get("hostname") or d.get("ip"),
        "ip": d.get("ip"),
        "mac": d.get("mac"),
        "vendor": d.get("vendor"),
        "online": bool(d.get("online")),
        "latency_ms": d.get("last_latency"),
        "loss_pct": d.get("last_loss"),
    }
