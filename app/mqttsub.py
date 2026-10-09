"""Client MQTT 3.1.1 abonné (asyncio, sans dépendance), complément du publieur de notify.py.

QoS 0 uniquement : le broker rejoue les messages « retained » à l'abonnement, ce qui suffit à
Zigbee2MQTT (état du pont, liste des appareils, disponibilité). Reconnexion automatique avec
temporisation croissante.
"""
from __future__ import annotations

import asyncio
import logging
import struct
import time
from typing import Awaitable, Callable

from .config import Config
from .notify import _mqtt_str, _remaining_length, mqtt_connect_packet

log = logging.getLogger("netwatch.mqtt")

MAX_PACKET = 8 * 1024 * 1024   # `bridge/devices` peut peser plusieurs centaines de Ko
KEEPALIVE = 30                  # annoncé dans mqtt_connect_packet
CONNACK_ERRORS = {
    1: "version de protocole refusée", 2: "identifiant client refusé", 3: "broker indisponible",
    4: "identifiant ou mot de passe MQTT refusé", 5: "connexion MQTT non autorisée",
}


class MQTTError(Exception):
    """Erreur lisible côté interface."""


def _why(e: BaseException) -> str:
    if isinstance(e, asyncio.IncompleteReadError):
        return "connexion fermée par le broker"
    return str(e) or "délai dépassé"


def subscribe_packet(packet_id: int, filters: list[str]) -> bytes:
    body = struct.pack("!H", packet_id) + b"".join(_mqtt_str(f) + b"\x00" for f in filters)
    return bytes([0x82]) + _remaining_length(len(body)) + body


def parse_publish(flags: int, body: bytes) -> tuple[str, bytes, int | None]:
    """Retourne (topic, charge utile, identifiant de paquet si QoS > 0)."""
    try:
        (tlen,) = struct.unpack("!H", body[:2])
        topic = body[2:2 + tlen].decode("utf-8", "replace")
        pos = 2 + tlen
        qos = (flags >> 1) & 3
        pid = None
        if qos:
            (pid,) = struct.unpack("!H", body[pos:pos + 2])
            pos += 2
    except struct.error as e:              # paquet tronqué : on coupe la session, elle sera rouverte
        raise MQTTError("paquet MQTT invalide") from e
    return topic, body[pos:], pid


async def read_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    """Lit un paquet complet : (octet d'en-tête, corps)."""
    head = (await reader.readexactly(1))[0]
    length, shift = 0, 0
    while True:
        b = (await reader.readexactly(1))[0]
        length |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
        if shift > 21:
            raise MQTTError("paquet MQTT invalide")
    if length > MAX_PACKET:
        raise MQTTError(f"paquet MQTT trop volumineux ({length} octets)")
    return head, (await reader.readexactly(length) if length else b"")


async def _connect(cfg: Config, client_id: str, filters: list[str]):
    """Ouvre la session et s'abonne. Retourne (reader, writer)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cfg.mqtt_host, int(cfg.mqtt_port)), 8)
    except (OSError, asyncio.TimeoutError) as e:
        raise MQTTError(f"broker {cfg.mqtt_host}:{cfg.mqtt_port} injoignable ({_why(e)})") from e
    try:
        writer.write(mqtt_connect_packet(client_id, cfg.mqtt_user or None, cfg.mqtt_password or None))
        await writer.drain()
        head, body = await asyncio.wait_for(read_packet(reader), 8)
        if head >> 4 != 2 or len(body) < 2:
            raise MQTTError("réponse inattendue du broker (ce n'est pas du MQTT ?)")
        if body[1] != 0:
            raise MQTTError(CONNACK_ERRORS.get(body[1], f"connexion refusée (code {body[1]})"))
        writer.write(subscribe_packet(1, filters))
        await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError) as e:
        writer.close()
        raise MQTTError(f"connexion MQTT interrompue ({_why(e)})") from e
    except Exception:
        writer.close()
        raise
    return reader, writer


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.write(b"\xe0\x00")
        await writer.drain()
    except OSError:
        pass
    writer.close()


async def probe(cfg: Config, filters: list[str], wait: float = 3.0,
                client_id: str = "netwatch-probe") -> dict[str, bytes]:
    """Connexion d'essai : s'abonne, collecte les messages reçus pendant `wait` s (dernier par topic).
    Lève MQTTError si la connexion échoue."""
    if not cfg.mqtt_host:
        raise MQTTError("aucun broker MQTT configuré")
    reader, writer = await _connect(cfg, client_id, filters)
    got: dict[str, bytes] = {}
    deadline = time.monotonic() + wait
    try:
        while (left := deadline - time.monotonic()) > 0:
            try:
                head, body = await asyncio.wait_for(read_packet(reader), left)
            except asyncio.TimeoutError:
                break
            if head >> 4 == 3:
                topic, payload, _ = parse_publish(head & 0x0F, body)
                got[topic] = payload
    except (asyncio.IncompleteReadError, OSError) as e:
        raise MQTTError(f"connexion MQTT interrompue ({e})") from e
    finally:
        await _close(writer)
    return got


class MQTTSubscriber:
    """Reste connecté au broker et transmet chaque message à `on_message(topic, payload)`."""

    def __init__(self, cfg: Config, filters: list[str], on_message: Callable[[str, bytes], Awaitable[None] | None],
                 client_id: str = "netwatch-z2m"):
        self.cfg, self.filters, self.on_message, self.client_id = cfg, filters, on_message, client_id
        self.connected = False
        self.error: str | None = None
        self.since: int | None = None        # début de la session courante
        self.last_message: int | None = None
        self.messages = 0

    async def run(self) -> None:
        delay = 2.0
        while True:
            try:
                reader, writer = await _connect(self.cfg, self.client_id, self.filters)
            except MQTTError as e:
                self.error = str(e)
                log.warning("mqtt: %s", e)
            else:
                self.connected, self.error, self.since, delay = True, None, int(time.time()), 2.0
                log.info("mqtt: abonné à %s", ", ".join(self.filters))
                ping = asyncio.create_task(self._pinger(writer))
                try:
                    await self._read_loop(reader, writer)
                except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError, MQTTError) as e:
                    self.error = f"connexion perdue ({_why(e)})"
                    log.warning("mqtt: %s", self.error)
                finally:
                    self.connected = False
                    ping.cancel()
                    writer.close()
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60.0)

    async def _pinger(self, writer: asyncio.StreamWriter) -> None:
        while True:
            await asyncio.sleep(KEEPALIVE / 2)
            writer.write(b"\xc0\x00")
            await writer.drain()

    async def _read_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            # le PINGRESP revient toutes les KEEPALIVE/2 s : le silence total signale une connexion morte
            head, body = await asyncio.wait_for(read_packet(reader), KEEPALIVE * 2)
            if head >> 4 != 3:
                continue          # SUBACK, PINGRESP…
            topic, payload, pid = parse_publish(head & 0x0F, body)
            if pid is not None and (head >> 1) & 3 == 1:   # QoS 1 : acquittement
                writer.write(bytes([0x40, 0x02]) + struct.pack("!H", pid))
            self.messages += 1
            self.last_message = int(time.time())
            try:
                res = self.on_message(topic, payload)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:  # noqa: BLE001
                log.exception("mqtt: traitement du message %s en échec", topic)
