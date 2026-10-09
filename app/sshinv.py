"""Gestion de l'inventaire SSH côté moteur : sélection des identifiants, limitation du nombre
d'essais (anti fail2ban), épinglage de la clé d'hôte (TOFU) et enregistrement des résultats.

Séparé de sshscan.py (connexion brute) pour que la logique de planification soit testable
avec un collecteur factice.
"""
from __future__ import annotations

import json
import logging
import time

from . import sshscan
from .vault import VaultError

log = logging.getLogger("netwatch.sshinv")


class SSHInventory:
    def __init__(self, cfg, db, vault, emit=None, collect=None):
        self.cfg = cfg
        self.db = db
        self.vault = vault
        self._emit = emit                       # coroutine(type, message, device, severity, data)
        self._collect = collect or sshscan.collect

    def enabled(self) -> bool:
        return self.cfg.ssh_enabled and sshscan.available() and not self.vault.locked

    def open_ssh_ports(self, device_id: int) -> set[int]:
        rows = self.db.q("SELECT port FROM ports WHERE device_id=? AND open=1 AND proto='tcp'", [device_id])
        return {r["port"] for r in rows}

    def _recent_failure(self, cred_id: int, device_id: int, now: int) -> bool:
        r = self.db.q1("SELECT ts, ok FROM ssh_attempts WHERE credential_id=? AND device_id=?",
                       [cred_id, device_id])
        return bool(r and not r["ok"] and now - r["ts"] < self.cfg.ssh_retry_after)

    def _record_attempt(self, cred_id, device_id, ok, error, now):
        self.db.x(
            "INSERT INTO ssh_attempts(credential_id, device_id, ts, ok, error) VALUES(?,?,?,?,?) "
            "ON CONFLICT(credential_id, device_id) DO UPDATE SET ts=excluded.ts, ok=excluded.ok, error=excluded.error",
            [cred_id, device_id, now, int(ok), error])
        col = "success_count" if ok else "failure_count"
        stamp = "last_success" if ok else "last_failure"
        self.db.x(f"UPDATE credentials SET {col}={col}+1, {stamp}=? WHERE id=?", [now, cred_id])

    def candidates(self, device: dict) -> list[dict]:
        """Identifiants à essayer pour cet appareil, dans l'ordre : celui qui a déjà marché
        d'abord, puis par priorité, en se limitant aux ports SSH ouverts s'ils sont connus."""
        did = device["id"]
        open_ports = self.open_ssh_ports(did) if device.get("last_deep_scan") else None
        cands = self.vault.candidates(device["ip"], open_ports)
        if getattr(self.cfg, "ssh_known_only", False) and not device.get("known"):
            # appareil non approuvé : on ne lui présente jamais un mot de passe (il pourrait le capturer)
            cands = [c for c in cands if c["auth_type"] == "key"]
        prev = self.db.q1("SELECT credential_id FROM device_ssh WHERE device_id=?", [did])
        if prev and prev["credential_id"]:
            cands.sort(key=lambda c: (c["id"] != prev["credential_id"], c["priority"]))
        return cands

    async def collect_device(self, device: dict) -> dict | None:
        """Tente l'inventaire d'un appareil. Retourne le dict device_ssh mis à jour, ou None
        si aucun identifiant applicable / SSH indisponible."""
        if not self.enabled():
            return None
        did, ip = device["id"], device["ip"]
        now = int(time.time())
        cands = self.candidates(device)
        if not cands:
            self._save(did, None, "no_credential", "aucun identifiant applicable", now)
            return None

        pin = self.db.q1("SELECT host_key, host_key_type FROM device_ssh WHERE device_id=?", [did])
        pinned = pin["host_key"] if pin else None
        tried = 0
        last_err = None
        for cred in cands:
            if tried >= self.cfg.ssh_max_attempts:
                break
            if self._recent_failure(cred["id"], did, now):
                continue
            try:
                secret, passphrase = self.vault.secrets_for(cred)
            except VaultError as e:
                last_err = str(e)
                continue
            tried += 1
            res = await self._collect(
                ip, cred["port"], cred["username"], secret, cred["auth_type"],
                passphrase=passphrase, pinned_key=pinned, use_sudo=bool(cred["use_sudo"]),
                connect_timeout=self.cfg.ssh_timeout, command_timeout=self.cfg.ssh_command_timeout)

            if res.kind == "hostkey_changed":
                await self._alert_hostkey(device)
                self._save(did, cred["id"], "hostkey_changed", res.error, now)
                return self.db.q1("SELECT * FROM device_ssh WHERE device_id=?", [did])

            if res.ok:
                self._record_attempt(cred["id"], did, True, None, now)
                first_key = pinned is None and res.host_key
                self._save(did, cred["id"], "ok", None, now, res, host_key=res.host_key,
                           host_key_type=res.host_key_type)
                if first_key:
                    log.info("Clé SSH épinglée pour %s (%s)", ip, res.fingerprint)
                await self._maybe_emit_inventory(device, res.inventory)
                return self.db.q1("SELECT * FROM device_ssh WHERE device_id=?", [did])

            last_err = res.error
            if res.kind == "auth":
                self._record_attempt(cred["id"], did, False, res.error, now)
            else:
                # hôte injoignable / timeout : ce n'est pas la faute de l'identifiant, on s'arrête
                self._save(did, None, res.kind, res.error, now)
                return self.db.q1("SELECT * FROM device_ssh WHERE device_id=?", [did])

        self._save(did, None, "auth_failed", last_err or "aucun identifiant valide", now)
        return self.db.q1("SELECT * FROM device_ssh WHERE device_id=?", [did])

    def _save(self, did, cred_id, status, error, now, res=None, host_key=None, host_key_type=None):
        fields = {"credential_id": cred_id, "status": status, "error": error, "last_attempt": now}
        if res and res.ok:
            fields.update(last_success=now, inventory_json=json.dumps(res.inventory, default=str),
                          duration=res.duration)
        if host_key:
            fields.update(host_key=host_key, host_key_type=host_key_type)
        if self.db.q1("SELECT device_id FROM device_ssh WHERE device_id=?", [did]):
            self.db.update2("device_ssh", "device_id", did, fields)
        else:
            cols = ", ".join(["device_id"] + list(fields))
            self.db.x(f"INSERT INTO device_ssh({cols}) VALUES({', '.join('?' * (len(fields)+1))})",
                      [did, *fields.values()])

    async def _emit_safe(self, *a, **k):
        if self._emit:
            await self._emit(*a, **k)

    async def _alert_hostkey(self, device):
        await self._emit_safe(
            "ssh_hostkey_changed",
            f"La clé SSH de {device.get('ip')} a changé depuis le dernier inventaire. "
            "Redémarrage/réinstallation légitime — ou interception. Inventaire suspendu pour cet hôte.",
            device, "critical", {"ip": device.get("ip")})

    async def _maybe_emit_inventory(self, device, inv):
        prev = self.db.q1("SELECT inventory_json FROM device_ssh WHERE device_id=?", [device["id"]])
        if not (prev and prev["inventory_json"]):
            await self._emit_safe(
                "ssh_inventory", f"Inventaire SSH réussi pour {device.get('ip')} "
                f"({(inv.get('os') or {}).get('name') or inv.get('kernel') or 'hôte'})",
                device, "info", {"hostname": inv.get("hostname")})
