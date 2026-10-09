"""Accès SQLite (WAL). Une connexion partagée protégée par un verrou : largement
suffisant pour un réseau domestique (quelques centaines d'appareils max)."""
from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
import time
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY,
    mac             TEXT UNIQUE NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'lan',      -- lan | external
    ip              TEXT,
    hostname        TEXT,
    hostname_source TEXT,
    names_json      TEXT,
    vendor          TEXT,
    random_mac      INTEGER NOT NULL DEFAULT 0,
    alias           TEXT,
    dev_type        TEXT,
    notes           TEXT,
    known           INTEGER NOT NULL DEFAULT 0,
    watch           INTEGER NOT NULL DEFAULT 0,
    online          INTEGER NOT NULL DEFAULT 0,
    missed          INTEGER NOT NULL DEFAULT 0,
    first_seen      INTEGER,
    last_seen       INTEGER,
    last_latency    REAL,
    last_loss       REAL,
    os_name         TEXT,
    os_accuracy     INTEGER,
    last_deep_scan  INTEGER,
    last_name_check INTEGER,
    alert_state     TEXT
);

CREATE TABLE IF NOT EXISTS samples (
    device_id INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    up        INTEGER NOT NULL,
    latency   REAL,
    loss      REAL
);
CREATE INDEX IF NOT EXISTS idx_samples_dev_ts ON samples(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);

CREATE TABLE IF NOT EXISTS samples_hourly (
    device_id INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    n         INTEGER NOT NULL,
    up_ratio  REAL,
    lat_avg   REAL,
    lat_min   REAL,
    lat_max   REAL,
    loss_avg  REAL,
    PRIMARY KEY (device_id, ts)
);

CREATE TABLE IF NOT EXISTS net_samples (
    ts          INTEGER PRIMARY KEY,
    online      INTEGER NOT NULL,
    total       INTEGER NOT NULL,
    avg_latency REAL
);

CREATE TABLE IF NOT EXISTS ports (
    device_id  INTEGER NOT NULL,
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL,
    service    TEXT,
    product    TEXT,
    version    TEXT,
    extra      TEXT,
    open       INTEGER NOT NULL DEFAULT 1,
    first_seen INTEGER,
    last_seen  INTEGER,
    PRIMARY KEY (device_id, port, proto)
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    device_id INTEGER,
    type      TEXT NOT NULL,
    severity  TEXT NOT NULL DEFAULT 'info',   -- info | warning | critical
    message   TEXT NOT NULL,
    data_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_dev ON events(device_id, ts);

CREATE TABLE IF NOT EXISTS scans (
    id       INTEGER PRIMARY KEY,
    type     TEXT NOT NULL,       -- discovery | deep
    started  INTEGER NOT NULL,
    finished INTEGER,
    hosts    INTEGER,
    detail   TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(type, started);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token    TEXT PRIMARY KEY,
    username TEXT,
    created  INTEGER,
    expires  INTEGER,
    ip       TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);

CREATE TABLE IF NOT EXISTS push_subscriptions (
    id           INTEGER PRIMARY KEY,
    endpoint     TEXT UNIQUE NOT NULL,
    p256dh       TEXT NOT NULL,
    auth         TEXT NOT NULL,
    notify_types TEXT,                          -- liste JSON des types d'alerte souscrits
    label        TEXT,                          -- nom de l'appareil (User-Agent simplifié)
    enabled      INTEGER NOT NULL DEFAULT 1,
    created      INTEGER,
    last_ok      INTEGER,
    last_error   TEXT,
    fail_count   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            INTEGER PRIMARY KEY,
    credential_id TEXT UNIQUE NOT NULL,       -- base64url
    public_key    TEXT NOT NULL,             -- base64url (COSE)
    sign_count    INTEGER NOT NULL DEFAULT 0,
    transports    TEXT,
    name          TEXT,
    created       INTEGER,
    last_used     INTEGER
);

-- V2 : identifiants SSH (secrets chiffrés par vault.py)
CREATE TABLE IF NOT EXISTS credentials (
    id             INTEGER PRIMARY KEY,
    name           TEXT NOT NULL,
    username       TEXT NOT NULL,
    auth_type      TEXT NOT NULL DEFAULT 'password',   -- password | key
    secret_enc     TEXT,
    passphrase_enc TEXT,
    port           INTEGER NOT NULL DEFAULT 22,
    scope_json     TEXT,                                -- liste de CIDR, vide = tout
    priority       INTEGER NOT NULL DEFAULT 100,
    use_sudo       INTEGER NOT NULL DEFAULT 0,          -- sudo -n pour dmidecode, etc.
    enabled        INTEGER NOT NULL DEFAULT 1,
    created        INTEGER,
    last_success   INTEGER,
    last_failure   INTEGER,
    success_count  INTEGER NOT NULL DEFAULT 0,
    failure_count  INTEGER NOT NULL DEFAULT 0
);

-- dernier essai de chaque couple (identifiant, appareil) : évite de marteler un hôte (fail2ban)
CREATE TABLE IF NOT EXISTS ssh_attempts (
    credential_id INTEGER NOT NULL,
    device_id     INTEGER NOT NULL,
    ts            INTEGER NOT NULL,
    ok            INTEGER NOT NULL,
    error         TEXT,
    PRIMARY KEY (credential_id, device_id)
);

CREATE TABLE IF NOT EXISTS device_ssh (
    device_id      INTEGER PRIMARY KEY,
    credential_id  INTEGER,
    status         TEXT,        -- ok | auth_failed | no_credential | hostkey_changed | error
    error          TEXT,
    last_attempt   INTEGER,
    last_success   INTEGER,
    host_key       TEXT,        -- empreinte SHA256 épinglée au premier contact (TOFU)
    host_key_type  TEXT,
    inventory_json TEXT,
    duration       REAL
);

-- compteurs et débits du lien WAN relevés sur la Bbox (débits en kbit/s, octets cumulés)
CREATE TABLE IF NOT EXISTS bbox_samples (
    ts       INTEGER PRIMARY KEY,
    rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL,
    rx_kbps  INTEGER NOT NULL,
    tx_kbps  INTEGER NOT NULL,
    rx_occ   INTEGER,
    tx_occ   INTEGER
);

-- Zigbee2MQTT : appareils connus du pont (clé = adresse IEEE)
CREATE TABLE IF NOT EXISTS z2m_devices (
    ieee     TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    type     TEXT,                     -- Coordinator | Router | EndDevice
    vendor   TEXT,
    model    TEXT,
    power    TEXT,                     -- Battery | Mains (single phase)…
    nwk      INTEGER,
    disabled INTEGER NOT NULL DEFAULT 0,
    present  INTEGER NOT NULL DEFAULT 1,
    online   INTEGER,                  -- dernier état de disponibilité connu (NULL = inconnu)
    online_ts INTEGER,
    last_msg INTEGER,                  -- dernier message reçu de l'appareil
    lqi      INTEGER,
    battery  INTEGER,
    updated  INTEGER
);

-- transitions de disponibilité ; ieee = 'bridge' pour l'état du pont Zigbee2MQTT lui-même
CREATE TABLE IF NOT EXISTS z2m_avail (
    ts     INTEGER NOT NULL,
    ieee   TEXT NOT NULL,
    online INTEGER NOT NULL,
    src    TEXT NOT NULL DEFAULT 'mqtt'     -- mqtt | init (état initial) | ha (import Home Assistant)
);
CREATE INDEX IF NOT EXISTS idx_z2m_avail ON z2m_avail(ieee, ts);

CREATE TABLE IF NOT EXISTS z2m_samples (
    ts      INTEGER NOT NULL,
    ieee    TEXT NOT NULL,
    lqi     INTEGER,
    battery INTEGER
);
CREATE INDEX IF NOT EXISTS idx_z2m_samples ON z2m_samples(ieee, ts);

-- journal Zigbee2MQTT : avertissements/erreurs et événements du réseau (départs, annonces…)
CREATE TABLE IF NOT EXISTS z2m_log (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    kind    TEXT NOT NULL,             -- log | device_leave | device_joined | device_announce | device_interview
    level   TEXT,
    ieee    TEXT,
    cat     TEXT,                      -- delivery | route | interview | other
    message TEXT
);
CREATE INDEX IF NOT EXISTS idx_z2m_log ON z2m_log(ts);

-- suivi Wi-Fi (voir wifi.py) : un relevé par appareil actif et par passage, et les sessions d'association
CREATE TABLE IF NOT EXISTS wifi_samples (
    ts   INTEGER NOT NULL,
    mac  TEXT NOT NULL,
    ap   TEXT NOT NULL,
    band TEXT,
    link TEXT,
    rssi INTEGER,
    rate INTEGER,
    PRIMARY KEY (mac, ts)
);
CREATE INDEX IF NOT EXISTS idx_wifi_samples_ts ON wifi_samples(ts);

CREATE TABLE IF NOT EXISTS wifi_sessions (
    id          INTEGER PRIMARY KEY,
    mac         TEXT NOT NULL,
    start       INTEGER NOT NULL,
    last_ts     INTEGER NOT NULL,
    end         INTEGER,
    ap          TEXT NOT NULL,
    band        TEXT,
    link        TEXT,
    rssi_first  INTEGER,
    rssi_last   INTEGER,
    rssi_min    INTEGER,
    samples     INTEGER NOT NULL DEFAULT 0,
    end_reason  TEXT              -- drop | roam | band | gap
);
CREATE INDEX IF NOT EXISTS idx_wifi_sessions_mac ON wifi_sessions(mac, start);

CREATE TABLE IF NOT EXISTS ip_conflicts (
    id          INTEGER PRIMARY KEY,
    ip          TEXT NOT NULL,
    macs_json   TEXT NOT NULL,
    source      TEXT NOT NULL,          -- arp_multi | flapping
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1,
    resolved    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_conflicts_ip ON ip_conflicts(ip, resolved);

CREATE TABLE IF NOT EXISTS diag_runs (
    id          INTEGER PRIMARY KEY,
    started     INTEGER NOT NULL,
    finished    INTEGER,
    trigger     TEXT NOT NULL,          -- scheduled | manual | anomaly
    device_id   INTEGER,
    summary     TEXT,
    result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_diag_started ON diag_runs(started);

-- constats du diagnostic, dédupliqués par clé : actifs tant que le problème est observé
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY,
    key           TEXT UNIQUE NOT NULL,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    title         TEXT NOT NULL,
    detail        TEXT,
    suggestion    TEXT,
    evidence_json TEXT,
    device_id     INTEGER,
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    run_id        INTEGER
);
"""

# colonnes ajoutées après la V1 : (table, colonne, définition)
MIGRATIONS = [
    ("samples", "jitter", "REAL"),
    ("samples_hourly", "jitter_avg", "REAL"),
    ("devices", "extra_ips", "TEXT"),
    ("devices", "baseline_latency", "REAL"),
    ("devices", "baseline_jitter", "REAL"),
    ("devices", "anomaly_state", "TEXT"),
    ("devices", "link_type", "TEXT"),          # wired | wifi | NULL (inconnu)
    ("devices", "excluded", "INTEGER NOT NULL DEFAULT 0"),  # exclu du scan par l'utilisateur
    ("z2m_devices", "ha_name", "TEXT"),        # nom de l'appareil dans Home Assistant
    ("z2m_devices", "ha_guess", "TEXT"),       # nom déduit (JSON : name, confidence, evidence) quand il n'y en a pas
]


class DB:
    def __init__(self, path: str):
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            if path != ":memory:":
                for suffix in ("", "-wal", "-shm"):      # la base n'est lisible que par NetWatch
                    with contextlib.suppress(OSError):
                        os.chmod(path + suffix, 0o600)
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA foreign_keys=OFF")
            self.conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        for table, col, decl in MIGRATIONS:
            cols = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            if col not in cols:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")

    # -- helpers ---------------------------------------------------------
    def q(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, tuple(params)).fetchall()]

    def q1(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        with self.lock:
            r = self.conn.execute(sql, tuple(params)).fetchone()
            return dict(r) if r else None

    def x(self, sql: str, params: Iterable[Any] = ()) -> int:
        with self.lock:
            cur = self.conn.execute(sql, tuple(params))
            return cur.lastrowid

    def xmany(self, sql: str, rows: list[tuple]) -> None:
        if not rows:
            return
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.executemany(sql, rows)
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def update(self, table: str, row_id: int, fields: dict) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        self.x(f"UPDATE {table} SET {cols} WHERE id=?", [*fields.values(), row_id])

    def update2(self, table: str, key_col: str, key_val, fields: dict) -> None:
        """Comme update() mais pour une table dont la clé n'est pas 'id'."""
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        self.x(f"UPDATE {table} SET {cols} WHERE {key_col}=?", [*fields.values(), key_val])

    # -- meta ------------------------------------------------------------
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        r = self.q1("SELECT value FROM meta WHERE key=?", [key])
        return r["value"] if r else default

    def set_meta(self, key: str, value: str) -> None:
        self.x(
            "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [key, value],
        )

    # -- events ----------------------------------------------------------
    def add_event(
        self,
        type_: str,
        message: str,
        device_id: int | None = None,
        severity: str = "info",
        data: dict | None = None,
        ts: int | None = None,
    ) -> dict:
        ts = ts or int(time.time())
        eid = self.x(
            "INSERT INTO events(ts,device_id,type,severity,message,data_json) VALUES(?,?,?,?,?,?)",
            [ts, device_id, type_, severity, message, json.dumps(data) if data else None],
        )
        return {
            "id": eid,
            "ts": ts,
            "device_id": device_id,
            "type": type_,
            "severity": severity,
            "message": message,
            "data": data,
        }

    # -- maintenance -----------------------------------------------------
    def rollup_hourly(self, now: int | None = None) -> None:
        """Agrège les échantillons bruts des heures terminées dans samples_hourly."""
        now = now or int(time.time())
        current_hour = now - now % 3600
        last = int(self.get_meta("rollup_until", "0") or 0)
        if last == 0:
            r = self.q1("SELECT MIN(ts) AS m FROM samples")
            if not r or r["m"] is None:
                return
            last = r["m"] - r["m"] % 3600
        if last >= current_hour:
            return
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO samples_hourly(device_id, ts, n, up_ratio, lat_avg, lat_min, lat_max,
                                                          loss_avg, jitter_avg)
                    SELECT device_id, (ts / 3600) * 3600 AS h, COUNT(*), AVG(up), AVG(latency),
                           MIN(latency), MAX(latency), AVG(loss), AVG(jitter)
                    FROM samples WHERE ts >= ? AND ts < ?
                    GROUP BY device_id, h
                    """,
                    (last, current_hour),
                )
                self.conn.execute(
                    "INSERT INTO meta(key,value) VALUES('rollup_until',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(current_hour),),
                )
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def purge(self, raw_days: int, hourly_days: int, event_days: int, now: int | None = None) -> None:
        now = now or int(time.time())
        self.x("DELETE FROM samples WHERE ts < ?", [now - raw_days * 86400])
        self.x("DELETE FROM net_samples WHERE ts < ?", [now - raw_days * 86400])
        self.x("DELETE FROM wifi_samples WHERE ts < ?", [now - raw_days * 86400])
        self.x("DELETE FROM wifi_sessions WHERE end IS NOT NULL AND end < ?", [now - hourly_days * 86400])
        self.x("DELETE FROM bbox_samples WHERE ts < ?", [now - max(raw_days, 90) * 86400])
        self.x("DELETE FROM z2m_samples WHERE ts < ?", [now - raw_days * 86400])
        self.x("DELETE FROM z2m_avail WHERE ts < ?", [now - event_days * 86400])
        self.x("DELETE FROM z2m_log WHERE ts < ?", [now - event_days * 86400])
        self.x("DELETE FROM samples_hourly WHERE ts < ?", [now - hourly_days * 86400])
        self.x("DELETE FROM events WHERE ts < ?", [now - event_days * 86400])
        self.x("DELETE FROM scans WHERE started < ?", [now - event_days * 86400])
        self.x("DELETE FROM diag_runs WHERE started < ?", [now - event_days * 86400])
        self.x("DELETE FROM findings WHERE active=0 AND last_seen < ?", [now - event_days * 86400])
        self.x("DELETE FROM ip_conflicts WHERE resolved=1 AND last_seen < ?", [now - event_days * 86400])
