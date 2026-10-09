"""Supervision de la box Internet (Bouygues, Free, Orange ou SFR) via son API locale.

Le fournisseur (app/boxes) sait lire la box ; ce moniteur s'occupe de ce qui est commun :
identifiants chiffrés par le coffre (vault.py, jamais renvoyés par l'API), relevé périodique sur une
session conservée, événements (redémarrage, firmware, Internet coupé), historique des débits et suivi
Wi-Fi. Après un refus d'authentification, on cesse d'essayer tant que les identifiants n'ont pas changé,
pour ne pas verrouiller la box.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from .boxes import PROVIDERS, BoxApprovalRequired, BoxAuthError, BoxError, detect, host_allowed, provider_list
from .boxes.bouygues import DEFAULT_HOST as BOUYGUES_HOST
from .config import Config
from .db import DB
from .wifi import WifiTracker, band_of, radios_changed, recommendations
from .vault import Vault, VaultError

log = logging.getLogger("netwatch.box")

META_PROVIDER = "box_provider"
META_USER = "box_username"
META_PASSWORD = "box_password"
META_TOKEN = "box_token"
LEGACY_PASSWORD = "bbox_password"      # nom utilisé quand seule la Bbox était prise en charge
META_BOOTS = "bbox_boots"
META_FIRMWARE = "bbox_firmware"
META_CHANNELS = "wifi_channels"


class BoxMonitor:
    def __init__(self, cfg: Config, db: DB, vault: Vault, emit, gateway=lambda: None):
        self.cfg, self.db, self.vault, self.emit, self.gateway = cfg, db, vault, emit, gateway
        self.lock = asyncio.Lock()
        self.snap: dict | None = None
        self.error: str | None = None
        self.last_poll: int | None = None
        self.auth_failed = False       # identifiants refusés : on attend qu'ils changent
        self.needs_approval = False    # Freebox : autorisation à confirmer sur la façade
        self.detected: list[dict] | None = None
        self._prev_uptime: int | None = None
        self._prev_internet: bool | None = None
        self._factory = lambda pid, host: PROVIDERS[pid](host)    # remplaçable dans les tests
        self._provider = None
        self._provider_key: tuple | None = None
        self._pending: dict | None = None     # autorisation Freebox en cours : {"app_token", "track_id"}
        self.tracker = WifiTracker(db)
        self.radios: dict | None = None
        self._migrate_legacy()

    def _migrate_legacy(self) -> None:
        old = self.db.get_meta(LEGACY_PASSWORD)
        if old and not self.db.get_meta(META_PASSWORD):
            self.db.set_meta(META_PASSWORD, old)
            if not self.db.get_meta(META_PROVIDER):
                self.db.set_meta(META_PROVIDER, "bouygues")    # l'ancienne version ne gérait que la Bbox

    # -- configuration
    def provider_id(self) -> str:
        pid = self.db.get_meta(META_PROVIDER) or ""
        if pid in PROVIDERS:
            return pid
        if self.detected:
            return self.detected[0]["provider"]
        return ""

    def set_provider(self, pid: str) -> None:
        if pid and pid not in PROVIDERS:
            raise ValueError("fournisseur inconnu")
        self.db.set_meta(META_PROVIDER, pid)
        self._reset_session()
        self.auth_failed = self.needs_approval = False
        self.snap = None

    def provider_cls(self):
        return PROVIDERS.get(self.provider_id())

    def host(self) -> str:
        explicit = (self.cfg.box_host or "").strip()
        if explicit:
            return explicit
        gw = self.gateway()
        if gw:
            return gw
        return BOUYGUES_HOST if self.provider_id() == "bouygues" else ""

    def _reset_session(self) -> None:
        p, self._provider, self._provider_key = self._provider, None, None
        if p is not None and p.authenticated:
            try:
                p.logout()
            except Exception:  # noqa: BLE001
                pass

    def username(self) -> str:
        cls = self.provider_cls()
        return self.db.get_meta(META_USER) or (cls.default_user if cls else "")

    def has_password(self) -> bool:
        return bool(self.db.get_meta(META_PASSWORD))

    def has_token(self) -> bool:
        return bool(self.db.get_meta(META_TOKEN))

    def has_credentials(self) -> bool:
        cls = self.provider_cls()
        if cls is not None and cls.auth == "approval":
            return self.has_token()
        return self.has_password()

    def _secret(self, key: str) -> str | None:
        token = self.db.get_meta(key)
        if not token:
            return None
        try:
            return self.vault.decrypt(token)
        except VaultError as e:
            self.error = f"secret indéchiffrable : {e}"
            return None

    def _creds(self) -> dict:
        return {"username": self.username(), "password": self._secret(META_PASSWORD),
                "token": self._secret(META_TOKEN)}

    def set_credentials(self, password: str, username: str | None = None) -> None:
        password = (password or "").strip("\r\n")
        if not password or len(password) > 256:
            raise ValueError("mot de passe vide ou trop long")
        self.db.set_meta(META_PASSWORD, self.vault.encrypt(password) or "")
        if username is not None:
            self.db.set_meta(META_USER, username.strip()[:64])
        self.auth_failed = False
        self._reset_session()          # nouvelle session avec les nouveaux identifiants

    def clear_credentials(self) -> None:
        for key in (META_PASSWORD, META_TOKEN, LEGACY_PASSWORD):
            self.db.x("DELETE FROM meta WHERE key=?", [key])
        self.auth_failed = False
        self._reset_session()
        if self.snap:
            self.snap["hosts"] = None

    # -- fournisseur
    def _get_provider(self):
        pid, host = self.provider_id(), self.host()
        if not pid:
            raise BoxError("box non reconnue : choisissez le fournisseur dans la page Box")
        if not host:
            raise BoxError("adresse de la box introuvable : renseignez-la dans la page Box")
        key = (pid, host)
        if self._provider is None or self._provider_key != key:
            self._provider, self._provider_key = self._factory(pid, host), key
        return self._provider

    async def detect(self) -> list[dict]:
        """Cherche la box à l'adresse configurée (ou la passerelle) et retient le résultat."""
        host = self.host() or self.gateway() or ""
        self.detected = await asyncio.to_thread(detect, host) if host else []
        return self.detected

    def _collect_blocking(self) -> dict:
        try:
            snap = self._get_provider().collect(self._creds())
        except BoxAuthError as e:
            self._reset_session()
            snap = None
            auth = str(e)
        else:
            auth = None
        if snap is None:
            from .boxes.base import empty_snapshot
            snap = empty_snapshot()
            snap["auth_error"] = auth
        return snap

    def _collect_once(self, creds: dict | None = None) -> dict:
        """Essai ponctuel : session jetable, fermée juste après."""
        provider = self._factory(self.provider_id(), self.host())
        try:
            return provider.collect(creds if creds is not None else self._creds())
        finally:
            if provider.authenticated:
                provider.logout()

    def close(self) -> None:
        """Ferme la session de la box (à l'arrêt de NetWatch)."""
        self._reset_session()

    async def test(self, password: str | None = None, username: str | None = None) -> dict:
        """Essai ponctuel (identifiants fournis ou enregistrés), sans rien conserver."""
        creds = self._creds()
        if password:
            creds["password"] = password
        if username:
            creds["username"] = username
        if not self.provider_id():
            await self.detect()
            if not self.provider_id():
                return {"ok": False, "error": "box non reconnue : choisissez le fournisseur"}
        try:
            snap = await asyncio.to_thread(self._collect_once, creds)
        except BoxApprovalRequired as e:
            return {"ok": False, "needs_approval": True, "error": str(e)}
        except BoxAuthError as e:
            return {"ok": False, "error": str(e)}
        except BoxError as e:
            return {"ok": False, "error": str(e)}
        has_creds = bool(creds.get("password") or creds.get("token"))
        res = {"ok": True, "provider": self.provider_id(), "model": snap["device"]["model"],
               "firmware": snap["device"]["firmware"],
               "authenticated": has_creds and snap["hosts"] is not None,
               "hosts": None if snap["hosts"] is None else len(snap["hosts"]),
               "endpoints": snap["endpoints"]}
        if snap["auth_error"]:
            res["ok"], res["error"] = False, snap["auth_error"]
        return res

    # -- autorisation par bouton (Freebox)
    async def start_approval(self) -> dict:
        cls = self.provider_cls()
        if cls is None or cls.auth != "approval":
            raise BoxError("ce fournisseur n'utilise pas d'autorisation par bouton")

        def go():
            return self._factory(self.provider_id(), self.host()).request_authorization()
        self._pending = await asyncio.to_thread(go)
        return {"track_id": self._pending["track_id"],
                "message": "Appuyez sur la flèche de la façade de la Freebox pour autoriser NetWatch."}

    async def approval_status(self) -> dict:
        if not self._pending:
            return {"status": "none"}

        def go():
            return self._factory(self.provider_id(), self.host()).authorization_status(self._pending["track_id"])
        status = await asyncio.to_thread(go)
        if status == "granted":
            self.db.set_meta(META_TOKEN, self.vault.encrypt(self._pending["app_token"]) or "")
            self._pending, self.auth_failed, self.needs_approval = None, False, False
            self._reset_session()
        elif status in ("denied", "timeout", "unknown"):
            self._pending = None
        return {"status": status}

    # -- relevé
    async def poll(self) -> dict | None:
        async with self.lock:
            return await self._poll()

    async def _poll(self) -> dict | None:
        if not self.provider_id():
            await self.detect()
        try:
            snap = await asyncio.to_thread(self._collect_public if self.auth_failed else self._collect_blocking)
        except BoxApprovalRequired:
            self.needs_approval, self.error = True, None
            return None
        except BoxError as e:
            self.error = str(e)
            return None
        except Exception as e:  # noqa: BLE001
            log.exception("Interrogation de la box en échec")
            self.error = str(e)
            return None
        self.needs_approval = False
        self.error = None
        now = int(time.time())
        self.last_poll = now
        if snap["auth_error"] and not self.auth_failed:
            self.auth_failed = True
            await self.emit("bbox_auth", "La box refuse les identifiants enregistrés. Mettez-les à jour "
                            "dans la page Box (NetWatch n'essaiera plus d'ici là).", None, "warning")
        self.snap = snap
        self._store_sample(now, snap["stats"])
        await self._detect_events(snap)
        if snap["hosts"] is not None and self.cfg.wifi_tracking:
            self.tracker.update(snap["hosts"], now, max_gap=max(180, 3 * self.cfg.box_interval))
        await self._detect_channels(snap.get("radios"))
        return snap

    def _collect_public(self) -> dict:
        """Relevé sans identifiants (après un refus) : seules les données publiques de la box."""
        creds = {"username": "", "password": None, "token": None}
        return self._get_provider().collect(creds)

    def _store_sample(self, ts: int, st: dict | None) -> None:
        if not st or st["rx_bytes"] is None or st["tx_bytes"] is None:
            return
        self.db.x("INSERT OR REPLACE INTO bbox_samples(ts, rx_bytes, tx_bytes, rx_kbps, tx_kbps, rx_occ, tx_occ) "
                  "VALUES(?,?,?,?,?,?,?)",
                  [ts, st["rx_bytes"], st["tx_bytes"], st["rx_kbps"], st["tx_kbps"],
                   st["rx_occ"], st["tx_occ"]])

    def _name(self) -> str:
        cls = self.provider_cls()
        return cls.ap_label if cls else "La box"

    async def _detect_events(self, snap: dict) -> None:
        dev, summ, name = snap["device"], snap["summary"], self._name()
        boots, uptime = dev["boots"], dev["uptime"]
        prev_boots = _int(self.db.get_meta(META_BOOTS))
        rebooted = (boots is not None and prev_boots is not None and boots > prev_boots) or (
            uptime is not None and self._prev_uptime is not None and uptime + 30 < self._prev_uptime)
        if rebooted:
            await self.emit("bbox_reboot", f"{name} a redémarré (en ligne depuis {_fmt_dur(uptime)}).",
                            None, "warning", {"uptime": uptime, "boots": boots})
        if boots is not None:
            self.db.set_meta(META_BOOTS, str(boots))
        self._prev_uptime = uptime

        fw, prev_fw = dev["firmware"], self.db.get_meta(META_FIRMWARE)
        if fw:
            if prev_fw and prev_fw != fw:
                await self.emit("bbox_firmware", f"Firmware de {name} mis à jour : {prev_fw} → {fw}.",
                                None, "info", {"from": prev_fw, "to": fw})
            self.db.set_meta(META_FIRMWARE, fw)

        up = summ["internet_up"]
        if up is not None:
            if self._prev_internet is not None and up != self._prev_internet:
                if up:
                    await self.emit("bbox_internet", f"{name} signale le retour d'Internet.", None, "info")
                else:
                    await self.emit("bbox_internet", f"{name} signale que la connexion Internet est coupée.",
                                    None, "critical")
            self._prev_internet = up

    async def _detect_channels(self, radios: dict | None) -> None:
        """Un changement de canal (radar DFS, optimisation automatique) coupe tous les appareils de la bande."""
        if not radios:
            return
        self.radios = radios
        for band, old, new in radios_changed(self.db.get_meta(META_CHANNELS), radios):
            why = " (canal radar : probablement un radar détecté)" if radios["bands"][band]["dfs"] else ""
            await self.emit("wifi_channel", f"Canal Wi-Fi {band} GHz modifié : {old} → {new}{why}.", None,
                            "warning" if radios["bands"][band]["dfs"] else "info",
                            {"band": band, "from": old, "to": new})
        self.db.set_meta(META_CHANNELS, json.dumps({b: v["channel"] for b, v in radios["bands"].items()}))

    # -- restitution
    def status(self) -> dict:
        s = self.snap or {}
        cls = self.provider_cls()
        return {
            "enabled": bool(self.cfg.box_enabled), "host": self.host(), "host_allowed": host_allowed(self.host()),
            "provider": cls.info() if cls else None, "providers": provider_list(),
            "detected": self.detected, "username": self.username(),
            "has_password": self.has_password(), "has_token": self.has_token(),
            "has_credentials": self.has_credentials(), "auth_failed": self.auth_failed,
            "needs_approval": self.needs_approval, "wifi_tracking": bool(self.cfg.wifi_tracking),
            "vault_locked": self.vault.locked, "interval": self.cfg.box_interval,
            "last_poll": self.last_poll, "error": self.error,
            "device": s.get("device"), "summary": s.get("summary"), "wan": s.get("wan"),
            "stats": s.get("stats"), "endpoints": s.get("endpoints") or {},
            "hosts": self.hosts(),
            "wifi": {"radios": self.radios, "recommendations": recommendations(self.radios)},
            "repeaters": None if s.get("repeaters") is None else [
                {"index": r["index"], "mac": r["mac"], "label": r["label"], "stations": len(r["stations"])}
                for r in s["repeaters"]],
        }

    def hosts(self) -> list[dict] | None:
        """Appareils de la box, croisés avec l'inventaire NetWatch (par adresse MAC)."""
        hosts = (self.snap or {}).get("hosts")
        if hosts is None:
            return None
        known = {r["mac"]: r for r in self.db.q("SELECT id, mac, alias, known, online FROM devices WHERE kind='lan'")}
        out = []
        for h in hosts:
            nw = known.get(h["mac"]) if h["mac"] else None
            out.append({**h, "band": band_of(h.get("link")) if h.get("wifi") else None,
                        "netwatch_id": nw["id"] if nw else None,
                        "netwatch_name": (nw or {}).get("alias")})
        out.sort(key=lambda h: (not h["active"], h.get("ap") or "", (h["hostname"] or h["ip"] or "").lower()))
        return out

    def usage(self, start: int, end: int, step: int) -> dict:
        """Débits moyens par tranche + volumes échangés (somme des écarts de compteurs)."""
        rows = self.db.q("SELECT ts, rx_bytes, tx_bytes, rx_kbps, tx_kbps FROM bbox_samples "
                         "WHERE ts >= ? AND ts <= ? ORDER BY ts", [start, end])
        rx_total = tx_total = 0
        buckets: dict[int, list] = {}
        prev = None
        for r in rows:
            if prev is not None:
                # un compteur qui recule = redémarrage de la box : on ignore cet écart
                if r["rx_bytes"] >= prev["rx_bytes"]:
                    rx_total += r["rx_bytes"] - prev["rx_bytes"]
                if r["tx_bytes"] >= prev["tx_bytes"]:
                    tx_total += r["tx_bytes"] - prev["tx_bytes"]
            prev = r
            b = buckets.setdefault(r["ts"] // step * step, [0, 0, 0, 0, 0])
            b[0] += r["rx_kbps"]
            b[1] += r["tx_kbps"]
            b[2] += 1
            b[3] = max(b[3], r["rx_kbps"])
            b[4] = max(b[4], r["tx_kbps"])
        series = [{"ts": t, "rx_kbps": round(b[0] / b[2]), "tx_kbps": round(b[1] / b[2]),
                   "rx_max": b[3], "tx_max": b[4]} for t, b in sorted(buckets.items())]
        return {"series": series, "rx_bytes": rx_total, "tx_bytes": tx_total}


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _fmt_dur(s: int | None) -> str:
    if s is None:
        return "?"
    if s < 3600:
        return f"{max(s // 60, 0)} min"
    if s < 86400:
        return f"{s // 3600} h"
    return f"{s // 86400} j"
