"""API HTTP (Starlette) + fichiers statiques de l'interface + flux temps réel SSE."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import json
import os
import secrets
import time
from collections import defaultdict

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import airscan
from .auth import Auth
from .boxes import host_allowed
from .config import Config
from .db import DB
from .engine import Engine
from .hahistory import HAError, url_allowed as ha_url_allowed
from .mqttsub import MQTTError
from .webauthn_mgr import WebAuthnManager

# réglages que l'assistant de configuration lit et propose
WIZARD_KEYS = ("scans_enabled", "deep_enabled", "ssh_enabled", "diag_enabled", "box_enabled", "wifi_tracking",
               "z2m_enabled", "z2m_topic", "mqtt_host", "mqtt_port", "mqtt_user", "ha_url", "ha_verify_tls")
WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")

RANGES = {  # clé -> (durée s, pas s, source)
    "1h": (3600, 60, "raw"),
    "6h": (6 * 3600, 120, "raw"),
    "24h": (86400, 600, "raw"),
    "7d": (7 * 86400, 3600, "raw"),
    "30d": (30 * 86400, 3 * 3600, "hourly"),
    "90d": (90 * 86400, 12 * 3600, "hourly"),
    "365d": (365 * 86400, 86400, "hourly"),
}
DEVICE_FIELDS = {"alias", "dev_type", "notes", "known", "watch", "excluded"}


def _range(req: Request) -> tuple[int, int, int, str]:
    key = req.query_params.get("range", "24h")
    dur, step, src = RANGES.get(key, RANGES["24h"])
    now = int(time.time())
    start = (now - dur) // step * step
    return start, now, step, src


def _r(v, n=2):
    return None if v is None else round(v, n)


def _wa_wrap(options_json: str, state: str) -> str:
    # options_json est déjà du JSON (produit par options_to_json) ; on l'embarque tel quel
    return '{"state": ' + json.dumps(state) + ', "options": ' + options_json + '}'


def _parse_cookies(header: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in header.split(";"):
        k, _, v = part.strip().partition("=")
        if k and v:
            out[k] = v
    return out


def _findings_out(rows: list[dict]) -> list[dict]:
    for r in rows:
        r["evidence"] = json.loads(r.pop("evidence_json") or "null")
        r["active"] = bool(r["active"])
    return rows


def create_app(cfg: Config, db: DB, engine: Engine) -> Starlette:
    auth = Auth(cfg, db)
    webauthn = WebAuthnManager(cfg, db)
    # installation existante (compte déjà créé) : pas d'assistant imposé ; il reste lançable depuis les Réglages
    if db.get_meta("wizard_done") is None and not auth.setup_required:
        db.set_meta("wizard_done", "1")

    # ------------------------------------------------------------ helpers
    def gateway_ip() -> str | None:
        return engine.net.gateway

    def client_ip(req: Request) -> str:
        return peer_ip(req.client.host if req.client else "?", req.headers.get("x-forwarded-for", ""))

    def peer_ip(peer: str, forwarded: str) -> str:
        """Adresse du visiteur. X-Forwarded-For n'est cru que s'il vient d'un proxy de confiance,
        sinon n'importe qui contournerait la limitation des tentatives en le falsifiant."""
        if forwarded and _trusted(peer):
            for hop in reversed([h.strip() for h in forwarded.split(",") if h.strip()]):
                if not _trusted(hop):
                    return hop[:64]
        return peer

    def _trusted(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in cfg.trusted_proxies:
            with contextlib.suppress(ValueError):
                if addr in ipaddress.ip_network(net, strict=False):
                    return True
        return False

    def cookie_secure(req: Request) -> bool:
        mode = (cfg.session_cookie_secure or "auto").lower()
        if mode in ("true", "1", "yes"):
            return True
        if mode in ("false", "0", "no"):
            return False
        return req.headers.get("x-forwarded-proto", req.url.scheme) == "https"

    def set_session_cookie(resp: Response, req: Request, token: str) -> None:
        resp.set_cookie("nw_session", token, max_age=auth.session_ttl, httponly=True,
                        samesite="strict", secure=cookie_secure(req), path="/")

    def enrich(d: dict) -> dict:
        d = dict(d)
        d["name"] = d.get("alias") or d.get("hostname") or (d.get("vendor") and f"{d['vendor']}") or d.get("ip")
        d["names"] = json.loads(d.pop("names_json") or "{}") if "names_json" in d else {}
        d["is_gateway"] = d.get("ip") == gateway_ip() and d.get("kind") == "lan"
        d["is_self"] = d.get("mac") == engine.net.mac
        d["online"] = bool(d.get("online"))
        d["known"] = bool(d.get("known"))
        d["watch"] = bool(d.get("watch"))
        d["excluded"] = bool(d.get("excluded"))
        d["random_mac"] = bool(d.get("random_mac"))
        return d

    # ------------------------------------------------------------ routes
    async def health(_: Request):
        return JSONResponse({"ok": True, "demo": cfg.demo})

    async def overview(_: Request):
        now = int(time.time())
        lan = db.q("SELECT * FROM devices WHERE kind='lan'")
        online = [d for d in lan if d["online"]]
        lat = [d["last_latency"] for d in online if d["last_latency"] is not None]
        ext = [enrich(d) for d in db.q("SELECT * FROM devices WHERE kind='external' ORDER BY id")]
        gw = next((d for d in lan if d["ip"] == gateway_ip()), None)
        events_24h = db.q1(
            "SELECT COUNT(*) AS n, SUM(severity!='info') AS w FROM events WHERE ts > ?", [now - 86400]
        )
        ports = db.q1("SELECT COUNT(*) AS n FROM ports WHERE open=1")["n"]
        # disponibilité moyenne 24 h des appareils surveillés
        avail = db.q1(
            """SELECT AVG(s.up) AS a FROM samples s JOIN devices d ON d.id=s.device_id
               WHERE d.kind='lan' AND d.watch=1 AND s.ts > ?""",
            [now - 86400],
        )["a"]
        return JSONResponse({
            "now": now,
            "demo": cfg.demo,
            "network": engine.net.as_dict(),
            "status": engine.status,
            "devices": {
                "total": len(lan),
                "online": len(online),
                "unknown": sum(1 for d in lan if not d["known"]),
                "watched": sum(1 for d in lan if d["watch"]),
                "watched_offline": sum(1 for d in lan if d["watch"] and not d["online"]),
                "new_24h": sum(1 for d in lan if (d["first_seen"] or 0) > now - 86400),
            },
            "latency": {
                "lan_avg": _r(sum(lat) / len(lat)) if lat else None,
                "lan_max": _r(max(lat)) if lat else None,
                "gateway": _r(gw["last_latency"]) if gw else None,
            },
            "external": [
                {"id": e["id"], "ip": e["ip"], "online": e["online"],
                 "latency": _r(e["last_latency"]), "loss": e["last_loss"]} for e in ext
            ],
            "open_ports": ports,
            "watched_availability_24h": _r(avail * 100, 2) if avail is not None else None,
            "events_24h": {"total": events_24h["n"] or 0, "warnings": events_24h["w"] or 0},
            "findings": {
                "active": db.q1("SELECT COUNT(*) AS n FROM findings WHERE active=1")["n"],
                "critical": db.q1("SELECT COUNT(*) AS n FROM findings WHERE active=1 AND severity='critical'")["n"],
            },
            "conflicts": db.q1("SELECT COUNT(*) AS n FROM ip_conflicts WHERE resolved=0")["n"],
            "ssh": {
                "enabled": engine.ssh.enabled(), "locked": engine.vault.locked, "reason": engine.vault.reason,
                "credentials": db.q1("SELECT COUNT(*) AS n FROM credentials WHERE enabled=1")["n"],
                "inventoried": db.q1("SELECT COUNT(*) AS n FROM device_ssh WHERE status='ok'")["n"],
            },
            "diag": engine.status.get("diag"),
        })

    async def overview_metrics(req: Request):
        start, now, step, src = _range(req)
        if src == "raw":
            rows = db.q(
                f"""SELECT (ts/{step})*{step} AS t, AVG(online) AS online, MAX(total) AS total,
                           AVG(avg_latency) AS lat
                    FROM net_samples WHERE ts >= ? GROUP BY t ORDER BY t""",
                [start],
            )
        else:
            rows = db.q(
                f"""SELECT t, SUM(up) AS online, COUNT(*) AS total, AVG(lat) AS lat FROM (
                      SELECT (h.ts/{step})*{step} AS t, h.device_id, AVG(h.up_ratio) AS up, AVG(h.lat_avg) AS lat
                      FROM samples_hourly h JOIN devices d ON d.id=h.device_id
                      WHERE d.kind='lan' AND h.ts >= ? GROUP BY t, h.device_id)
                    GROUP BY t ORDER BY t""",
                [start],
            )
        series = {
            "t": [r["t"] for r in rows],
            "online": [_r(r["online"], 1) for r in rows],
            "total": [r["total"] for r in rows],
            "lan_latency": [_r(r["lat"]) for r in rows],
        }
        # latence des cibles externes + passerelle
        ext = db.q("SELECT id, ip, kind FROM devices WHERE kind='external' ORDER BY id")
        gw = db.q1("SELECT id, ip FROM devices WHERE kind='lan' AND ip=?", [gateway_ip()]) if gateway_ip() else None
        targets = ([{"id": gw["id"], "label": f"Passerelle {gw['ip']}"}] if gw else []) + [
            {"id": e["id"], "label": e["ip"]} for e in ext
        ]
        grid = list(range(start, now + 1, step))
        out_targets = []
        for tg in targets:
            pts = {r["t"]: r for r in _device_series(tg["id"], start, step, src)}
            out_targets.append({
                "label": tg["label"], "id": tg["id"],
                "latency": [_r(pts[t]["lat"]) if t in pts else None for t in grid],
                "loss": [_r(pts[t]["loss"], 1) if t in pts else None for t in grid],
            })
        return JSONResponse({"step": step, "series": series, "grid": grid, "targets": out_targets})

    def _device_series(did: int, start: int, step: int, src: str) -> list[dict]:
        if src == "raw":
            return db.q(
                f"""SELECT (ts/{step})*{step} AS t, AVG(latency) AS lat, MIN(latency) AS lmin,
                           MAX(latency) AS lmax, AVG(up) AS up, AVG(loss) AS loss, COUNT(*) AS n
                    FROM samples WHERE device_id=? AND ts >= ? GROUP BY t ORDER BY t""",
                [did, start],
            )
        return db.q(
            f"""SELECT (ts/{step})*{step} AS t, AVG(lat_avg) AS lat, MIN(lat_min) AS lmin,
                       MAX(lat_max) AS lmax, AVG(up_ratio) AS up, AVG(loss_avg) AS loss, SUM(n) AS n
                FROM samples_hourly WHERE device_id=? AND ts >= ? GROUP BY t ORDER BY t""",
            [did, start],
        )

    async def devices(_: Request):
        now = int(time.time())
        rows = db.q(
            """SELECT d.*, (SELECT COUNT(*) FROM ports p WHERE p.device_id=d.id AND p.open=1) AS open_ports
               FROM devices d ORDER BY d.kind DESC, d.online DESC,
               CAST(replace(d.ip, '.', '') AS INTEGER)"""
        )
        # mini-courbes : latence sur la dernière heure, pas de 2 min
        spark = defaultdict(lambda: [None] * 30)
        base = (now - 3600) // 120 * 120
        for r in db.q(
            "SELECT device_id, (ts/120)*120 AS t, AVG(latency) AS lat FROM samples WHERE ts >= ? GROUP BY device_id, t",
            [base],
        ):
            i = (r["t"] - base) // 120
            if 0 <= i < 30:
                spark[r["device_id"]][i] = _r(r["lat"])
        out = []
        for r in rows:
            d = enrich(r)
            d["spark"] = spark[r["id"]]
            out.append(d)
        # tri naturel des IP
        def ipkey(d):
            try:
                return (d["kind"] != "lan", tuple(int(x) for x in d["ip"].split(".")))
            except (ValueError, AttributeError):
                return (True, (999,))
        out.sort(key=ipkey)
        return JSONResponse(out)

    async def device(req: Request):
        did = int(req.path_params["id"])
        d = db.q1("SELECT * FROM devices WHERE id=?", [did])
        if not d:
            return JSONResponse({"error": "introuvable"}, 404)
        d = enrich(d)
        d["ports"] = db.q("SELECT * FROM ports WHERE device_id=? ORDER BY open DESC, port", [did])
        d["events"] = db.q("SELECT * FROM events WHERE device_id=? ORDER BY ts DESC LIMIT 50", [did])
        now = int(time.time())
        for key, dur in (("availability_24h", 86400), ("availability_7d", 7 * 86400)):
            a = db.q1("SELECT AVG(up) AS a FROM samples WHERE device_id=? AND ts > ?", [did, now - dur])["a"]
            d[key] = _r(a * 100, 2) if a is not None else None
        st = db.q1(
            "SELECT AVG(latency) AS avg, MIN(latency) AS mn, MAX(latency) AS mx, AVG(loss) AS loss "
            "FROM samples WHERE device_id=? AND ts > ? AND up=1", [did, now - 86400])
        d["stats_24h"] = {k: _r(v) for k, v in st.items()}
        d["deep_pending"] = did in engine.deep_pending
        ssh = db.q1("SELECT * FROM device_ssh WHERE device_id=?", [did])
        if ssh:
            d["ssh"] = {
                "status": ssh["status"], "error": ssh["error"], "last_success": ssh["last_success"],
                "last_attempt": ssh["last_attempt"], "duration": ssh["duration"],
                "credential_id": ssh["credential_id"], "host_key_type": ssh["host_key_type"],
                "inventory": json.loads(ssh["inventory_json"]) if ssh["inventory_json"] else None,
            }
        else:
            d["ssh"] = None
        d["conflicts"] = db.q(
            "SELECT * FROM ip_conflicts WHERE ip=? AND resolved=0", [d.get("ip")]) if d.get("ip") else []
        d["findings"] = _findings_out(db.q(
            "SELECT * FROM findings WHERE device_id=? AND active=1 ORDER BY first_seen DESC", [did]))
        return JSONResponse(d)

    async def device_patch(req: Request):
        did = int(req.path_params["id"])
        if not db.q1("SELECT id FROM devices WHERE id=?", [did]):
            return JSONResponse({"error": "introuvable"}, 404)
        body = await _json(req)
        fields = {}
        for k, v in body.items():
            if k not in DEVICE_FIELDS:
                continue
            if k in ("known", "watch", "excluded"):
                v = int(bool(v))
            elif v is not None:
                v = str(v).strip()[:200] or None
            fields[k] = v
        db.update("devices", did, fields)
        if "excluded" in fields:
            engine._refresh_excluded()  # applique tout de suite, sans attendre le cycle suivant
        engine.broadcast({"type": "device", "id": did})
        return JSONResponse(enrich(db.q1("SELECT * FROM devices WHERE id=?", [did])))

    async def device_delete(req: Request):
        did = int(req.path_params["id"])
        for t in ("samples", "samples_hourly", "ports"):
            db.x(f"DELETE FROM {t} WHERE device_id=?", [did])
        db.x("UPDATE events SET device_id=NULL WHERE device_id=?", [did])
        db.x("DELETE FROM devices WHERE id=? AND kind='lan'", [did])
        return JSONResponse({"ok": True})

    async def device_metrics(req: Request):
        did = int(req.path_params["id"])
        start, now, step, src = _range(req)
        pts = {r["t"]: r for r in _device_series(did, start, step, src)}
        grid = list(range(start, now + 1, step))
        return JSONResponse({
            "step": step, "t": grid,
            "latency": [_r(pts[t]["lat"]) if t in pts else None for t in grid],
            "lat_min": [_r(pts[t]["lmin"]) if t in pts else None for t in grid],
            "lat_max": [_r(pts[t]["lmax"]) if t in pts else None for t in grid],
            "up": [_r(pts[t]["up"], 3) if t in pts else None for t in grid],
            "loss": [_r(pts[t]["loss"], 1) if t in pts else None for t in grid],
        })

    async def device_scan(req: Request):
        did = int(req.path_params["id"])
        sid = await engine.enqueue_deep([did], "deep-manual")
        return JSONResponse({"queued": sid is not None})

    async def heatmap(req: Request):
        key = req.query_params.get("range", "24h")
        now = int(time.time())
        if key == "7d":
            step, start, src = 3 * 3600, (now - 7 * 86400) // (3 * 3600) * 3 * 3600, "raw"
        else:
            step, start, src = 3600, (now - 86400) // 3600 * 3600, "raw"
        devs = db.q(
            """SELECT * FROM devices WHERE kind='lan' AND (watch=1 OR last_seen >= ?)""", [start]
        )
        devs = [enrich(d) for d in devs]
        devs.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")) if d.get("ip") else (999,))
        grid = list(range(start, now + 1, step))
        idx = {t: i for i, t in enumerate(grid)}
        pos = {d["id"]: i for i, d in enumerate(devs)}
        lat = [[None] * len(grid) for _ in devs]
        up = [[None] * len(grid) for _ in devs]
        for r in db.q(
            f"""SELECT device_id, (ts/{step})*{step} AS t, AVG(latency) AS lat, AVG(up) AS up
                FROM samples WHERE ts >= ? GROUP BY device_id, t""",
            [start],
        ):
            if r["device_id"] in pos and r["t"] in idx:
                lat[pos[r["device_id"]]][idx[r["t"]]] = _r(r["lat"])
                up[pos[r["device_id"]]][idx[r["t"]]] = _r(r["up"], 3)
        return JSONResponse({
            "step": step, "t": grid,
            "devices": [{"id": d["id"], "name": d["name"], "ip": d["ip"], "watch": d["watch"]} for d in devs],
            "latency": lat, "up": up,
        })

    async def events(req: Request):
        try:
            limit = max(1, min(int(req.query_params.get("limit", 200)), 1000))
        except ValueError:
            limit = 200
        typ = req.query_params.get("type")
        did = req.query_params.get("device")
        where, params = [], []
        if typ:
            where.append("e.type = ?")
            params.append(typ)
        if did:
            where.append("e.device_id = ?")
            params.append(int(did))
        sql = """SELECT e.*, COALESCE(d.alias, d.hostname, d.ip) AS device_name FROM events e
                 LEFT JOIN devices d ON d.id = e.device_id"""
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY e.ts DESC, e.id DESC LIMIT ?"
        rows = db.q(sql, [*params, limit])
        for r in rows:
            r["data"] = json.loads(r.pop("data_json") or "null")
        return JSONResponse(rows)

    async def scans(_: Request):
        rows = db.q("SELECT * FROM scans ORDER BY started DESC LIMIT 100")
        for r in rows:
            r["detail"] = json.loads(r["detail"] or "null")
        return JSONResponse(rows)

    async def scan_now(req: Request):
        kind = req.path_params["kind"]
        if kind == "discovery":
            if engine.status["discovery"]["running"]:
                return JSONResponse({"queued": False, "reason": "déjà en cours"})
            asyncio.create_task(engine.discovery_cycle())
            return JSONResponse({"queued": True})
        if kind == "deep":
            ids = [r["id"] for r in db.q("SELECT id FROM devices WHERE kind='lan' AND online=1")]
            sid = await engine.enqueue_deep(ids, "deep-manual")
            return JSONResponse({"queued": sid is not None, "hosts": len(ids)})
        return JSONResponse({"error": "type inconnu"}, 400)

    async def stream(req: Request):
        q = engine.subscribe()

        async def gen():
            try:
                yield "retry: 5000\n\n"
                while True:
                    if await req.is_disconnected():
                        break
                    try:
                        msg = await asyncio.wait_for(q.get(), 15)
                        yield f"data: {json.dumps(msg, default=str)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": ping\n\n"
            finally:
                engine.unsubscribe(q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ------------------------------------------------------------ V2 : identifiants SSH
    async def creds_list(_: Request):
        return JSONResponse({"locked": engine.vault.locked, "reason": engine.vault.reason,
                             "available": engine.ssh.enabled(), "credentials": engine.vault.list()})

    async def creds_create(req: Request):
        if engine.vault.locked:
            return JSONResponse({"error": engine.vault.reason or "coffre verrouillé"}, 409)
        try:
            body = await req.json()
            out = engine.vault.create(body)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        engine.status["ssh"] = {"enabled": engine.ssh.enabled(), "locked": engine.vault.locked,
                                "reason": engine.vault.reason}
        return JSONResponse(out, 201)

    async def creds_update(req: Request):
        cid = int(req.path_params["id"])
        try:
            out = engine.vault.update(cid, await req.json())
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        if out is None:
            return JSONResponse({"error": "introuvable"}, 404)
        return JSONResponse(out)

    async def creds_delete(req: Request):
        engine.vault.delete(int(req.path_params["id"]))
        return JSONResponse({"ok": True})

    async def creds_test(req: Request):
        """Teste un identifiant contre un hôte donné, sans rien enregistrer."""
        cid = int(req.path_params["id"])
        body = await req.json()
        ip = str(body.get("ip") or "").strip()
        row = db.q1("SELECT * FROM credentials WHERE id=?", [cid])
        if not row or not ip:
            return JSONResponse({"error": "identifiant ou IP manquant"}, 400)
        # le secret ne part que vers un hôte du réseau surveillé, dans la portée de l'identifiant :
        # sinon cette route servirait à l'envoyer à n'importe quelle machine
        from .vault import in_scope
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return JSONResponse({"error": "adresse IP invalide"}, 400)
        net = engine.net.network
        if not (net and addr in net) or not in_scope(ip, json.loads(row["scope_json"] or "[]")):
            return JSONResponse({"error": "hôte hors du réseau surveillé ou hors de la portée de l'identifiant"}, 400)
        from . import sshscan
        try:
            secret, passphrase = engine.vault.secrets_for(row)
        except Exception as e:  # noqa: BLE001
            return JSONResponse({"ok": False, "error": str(e)})
        res = await sshscan.collect(
            ip, row["port"], row["username"], secret, row["auth_type"], passphrase=passphrase,
            use_sudo=bool(row["use_sudo"]), connect_timeout=cfg.ssh_timeout,
            command_timeout=cfg.ssh_command_timeout)
        return JSONResponse({"ok": res.ok, "kind": res.kind, "error": res.error,
                             "fingerprint": res.fingerprint, "duration": res.duration,
                             "hostname": (res.inventory or {}).get("hostname") if res.ok else None})

    # ------------------------------------------------------------ V2 : conflits / diagnostics / constats
    async def conflicts(req: Request):
        show_all = req.query_params.get("all") == "1"
        sql = "SELECT * FROM ip_conflicts" + ("" if show_all else " WHERE resolved=0") + " ORDER BY last_seen DESC LIMIT 200"
        rows = db.q(sql)
        for r in rows:
            r["macs"] = json.loads(r.pop("macs_json") or "[]")
        return JSONResponse(rows)

    async def findings(req: Request):
        show_all = req.query_params.get("all") == "1"
        sql = "SELECT * FROM findings" + ("" if show_all else " WHERE active=1")
        sql += " ORDER BY active DESC, first_seen DESC LIMIT 300"
        return JSONResponse(_findings_out(db.q(sql)))

    async def diag_runs(_: Request):
        rows = db.q("SELECT id, started, finished, trigger, device_id, summary FROM diag_runs ORDER BY started DESC LIMIT 50")
        return JSONResponse(rows)

    async def diag_run_get(req: Request):
        rid = int(req.path_params["id"])
        r = db.q1("SELECT * FROM diag_runs WHERE id=?", [rid])
        if not r:
            return JSONResponse({"error": "introuvable"}, 404)
        r["result"] = json.loads(r.pop("result_json") or "null")
        return JSONResponse(r)

    async def diag_start(req: Request):
        if cfg.demo:
            return JSONResponse({"error": "diagnostic indisponible en mode démo"}, 400)
        body = {}
        with contextlib.suppress(Exception):
            body = await req.json()
        did = body.get("device_id")
        if engine.diag_lock.locked():
            return JSONResponse({"started": False, "reason": "un diagnostic est déjà en cours"})
        asyncio.create_task(engine.run_diagnostic("manual", int(did) if did else None))
        return JSONResponse({"started": True})

    # ------------------------------------------------------------ notifications push
    async def push_config(_: Request):
        from .push import EVENT_TYPES
        return JSONResponse({
            "available": engine.push.available,
            "vapid_public_key": engine.push.application_server_key,
            "event_types": [{"key": k, "label": lbl, "default": on} for k, lbl, on in EVENT_TYPES],
            "subscriptions": engine.push.list(),
        })

    async def push_subscribe(req: Request):
        if not engine.push.available:
            return JSONResponse({"error": "push indisponible"}, 400)
        body = await req.json()
        try:
            out = engine.push.subscribe(body.get("subscription") or {}, body.get("notify_types"),
                                        req.headers.get("user-agent"))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        return JSONResponse(out, 201)

    async def push_update(req: Request):
        body = await req.json()
        endpoint = (body.get("subscription") or {}).get("endpoint") or body.get("endpoint")
        if not endpoint:
            return JSONResponse({"error": "endpoint manquant"}, 400)
        out = engine.push.update(endpoint, body.get("notify_types"), body.get("enabled"))
        if out is None:
            return JSONResponse({"error": "abonnement inconnu"}, 404)
        return JSONResponse(out)

    async def push_unsubscribe(req: Request):
        body = await req.json()
        endpoint = (body.get("subscription") or {}).get("endpoint") or body.get("endpoint")
        if endpoint:
            engine.push.unsubscribe(endpoint)
        elif body.get("endpoint_tail"):
            engine.push.unsubscribe_tail(body["endpoint_tail"])
        return JSONResponse({"ok": True})

    async def push_test(req: Request):
        body = {}
        with contextlib.suppress(Exception):
            body = await req.json()
        endpoint = (body.get("subscription") or {}).get("endpoint") or body.get("endpoint")
        ok = await asyncio.to_thread(engine.push.send_test, endpoint) if endpoint else False
        return JSONResponse({"ok": bool(ok)})

    # ------------------------------------------------------------ biométrie (WebAuthn / passkeys)
    def _wa_origin(req: Request) -> str | None:
        # l'en-tête Origin du navigateur est la source fiable (port inclus)
        o = req.headers.get("origin")
        if o:
            return o
        host = req.headers.get("x-forwarded-host") or req.headers.get("host")
        proto = req.headers.get("x-forwarded-proto", req.url.scheme)
        return f"{proto}://{host}" if host else None

    async def wa_register_options(req: Request):
        if not webauthn.available:
            return JSONResponse({"error": "biométrie indisponible"}, 400)
        options, state = webauthn.begin_registration(auth.username, _wa_origin(req))
        return Response(_wa_wrap(options, state), media_type="application/json")

    async def wa_register_verify(req: Request):
        body = await req.json()
        ok, err = webauthn.complete_registration(
            body.get("credential"), body.get("state", ""), _wa_origin(req), body.get("name"))
        if not ok:
            return JSONResponse({"error": err or "échec"}, 400)
        return JSONResponse({"ok": True})

    async def wa_auth_options(req: Request):
        if not (webauthn.available and webauthn.has_credentials()):
            return JSONResponse({"error": "aucun passkey enregistré"}, 400)
        res = webauthn.begin_authentication(_wa_origin(req))
        if not res:
            return JSONResponse({"error": "aucun passkey"}, 400)
        options, state = res
        return Response(_wa_wrap(options, state), media_type="application/json")

    async def wa_auth_verify(req: Request):
        ip = client_ip(req)
        if auth.locked_for(ip, password=False):
            return JSONResponse({"error": "trop de tentatives"}, 429)
        body = await _json(req)
        cred = body.get("credential") or {}
        if not isinstance(cred, dict):
            cred = {}
        ok = webauthn.complete_authentication(cred, body.get("state", ""), _wa_origin(req), cred.get("id", ""))
        if not ok:
            auth.record_failure(ip)
            return JSONResponse({"error": "authentification biométrique refusée"}, 401)
        auth.record_success(ip)
        token, _ = auth.create_session(ip)
        resp = JSONResponse({"authenticated": True, "username": auth.username})
        set_session_cookie(resp, req, token)
        return resp

    async def wa_list(_: Request):
        return JSONResponse({"available": webauthn.available, "credentials": webauthn.list()})

    async def wa_delete(req: Request):
        webauthn.delete(int(req.path_params["id"]))
        return JSONResponse({"ok": True})

    # ------------------------------------------------------------ réglages
    async def settings_get(_: Request):
        from . import settings as st
        return JSONResponse(st.public(cfg))

    async def settings_patch(req: Request):
        from . import settings as st
        body = await req.json()
        result = st.apply(cfg, db, body)
        if result["applied"]:
            engine.apply_settings_side_effects(result["applied"])
        return JSONResponse(result)

    # ------------------------------------------------------------ box Internet
    async def _json(req: Request) -> dict:
        body = {}
        with contextlib.suppress(Exception):
            body = await req.json()
        return body if isinstance(body, dict) else {}

    async def box_status(_: Request):
        return JSONResponse(engine.box.status())

    async def box_refresh(_: Request):
        if not cfg.box_enabled:
            return JSONResponse({"error": "supervision de la box désactivée (Réglages)"}, 400)
        await engine.box.poll()
        return JSONResponse(engine.box.status())

    async def box_detect(_: Request):
        await engine.box.detect()
        return JSONResponse(engine.box.status())

    async def box_provider_set(req: Request):
        body = await _json(req)
        try:
            engine.box.set_provider(str(body.get("provider") or ""))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        if cfg.box_enabled:
            await engine.box.poll()
        return JSONResponse(engine.box.status())

    async def box_credentials_set(req: Request):
        body = await _json(req)
        if engine.vault.locked:
            return JSONResponse({"error": "coffre verrouillé : " + (engine.vault.reason or "")}, 409)
        if not host_allowed(engine.box.host()):
            return JSONResponse({"error": "adresse de la box refusée (IP privée ou nom de box connu)"}, 400)
        try:
            engine.box.set_credentials(str(body.get("password", "")),
                                       None if body.get("username") is None else str(body.get("username")))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        if cfg.box_enabled:
            await engine.box.poll()
        return JSONResponse(engine.box.status())

    async def box_credentials_delete(_: Request):
        engine.box.clear_credentials()
        return JSONResponse(engine.box.status())

    async def box_test(req: Request):
        body = await _json(req)
        return JSONResponse(await engine.box.test(str(body.get("password") or "") or None,
                                                  str(body.get("username") or "") or None))

    async def box_approval_start(_: Request):
        if engine.vault.locked:
            return JSONResponse({"error": "coffre verrouillé : " + (engine.vault.reason or "")}, 409)
        try:
            return JSONResponse(await engine.box.start_approval())
        except Exception as e:  # noqa: BLE001
            return JSONResponse({"error": str(e)}, 400)

    async def box_approval_status(_: Request):
        try:
            res = await engine.box.approval_status()
        except Exception as e:  # noqa: BLE001
            return JSONResponse({"error": str(e)}, 400)
        if res["status"] == "granted" and cfg.box_enabled:
            await engine.box.poll()
        return JSONResponse({**res, "box": engine.box.status()})

    async def box_usage(req: Request):
        start, now, step, _src = _range(req)
        return JSONResponse({**engine.box.usage(start, now, step), "start": start, "end": now, "step": step})

    # ------------------------------------------------------------ assistant de configuration
    def _wizard_state() -> dict:
        net = engine.net
        return {
            "done": db.get_meta("wizard_done") == "1",
            "network": {"interface": getattr(net, "interface", None), "ip": getattr(net, "ip", None),
                        "gateway": getattr(net, "gateway", None),
                        "subnet": str(net.network) if getattr(net, "network", None) else None},
            "settings": {k: getattr(cfg, k, None) for k in WIZARD_KEYS},
            "box": engine.box.status(),
            "z2m": engine.z2m.status(),
            "ntfy": bool(cfg.ntfy_url),
        }

    async def wizard_get(_: Request):
        return JSONResponse(_wizard_state())

    async def wizard_complete(_: Request):
        db.set_meta("wizard_done", "1")
        engine.apply_settings_side_effects({})
        return JSONResponse({"ok": True})

    async def wizard_reset(_: Request):
        db.set_meta("wizard_done", "0")
        return JSONResponse({"ok": True})

    # ------------------------------------------------------------ Zigbee2MQTT
    def _hours(v, default=24) -> int:
        try:
            return max(1, min(int(v), 168))
        except (TypeError, ValueError):
            return default

    async def z2m_status(_: Request):
        return JSONResponse(engine.z2m.status())

    async def z2m_report(req: Request):
        return JSONResponse(engine.z2m.report(_hours(req.query_params.get("hours"))))

    async def z2m_test(_: Request):
        return JSONResponse(await engine.z2m.test())

    async def z2m_networkmap(_: Request):
        try:
            await engine.z2m.request_networkmap()
        except MQTTError as e:
            return JSONResponse({"ok": False, "error": str(e)})
        return JSONResponse({"ok": True})

    async def z2m_import(req: Request):
        body = {}
        with contextlib.suppress(Exception):
            body = await req.json()
        try:
            return JSONResponse({"ok": True, **await engine.z2m.import_ha(_hours(body.get("hours")))})
        except HAError as e:
            return JSONResponse({"ok": False, "error": str(e)})

    async def _secret_set(req: Request, setter, key: str):
        body = {}
        with contextlib.suppress(Exception):
            body = await req.json()
        if engine.vault.locked:
            return JSONResponse({"error": "coffre verrouillé : " + (engine.vault.reason or "")}, 409)
        try:
            setter(str(body.get(key, "")))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        return JSONResponse(engine.z2m.status())

    async def mqtt_password_set(req: Request):
        return await _secret_set(req, engine.z2m.set_mqtt_password, "password")

    async def mqtt_password_delete(_: Request):
        engine.z2m.clear_mqtt_password()
        return JSONResponse(engine.z2m.status())

    async def ha_token_set(req: Request):
        if cfg.ha_url and not ha_url_allowed(cfg.ha_url):
            return JSONResponse({"error": "URL refusée : le jeton ne part que vers une adresse locale"}, 400)
        return await _secret_set(req, engine.z2m.set_ha_token, "token")

    async def ha_token_delete(_: Request):
        engine.z2m.clear_ha_token()
        return JSONResponse(engine.z2m.status())

    async def box_wifi(req: Request):
        from . import wifi
        start, now, _step, _src = _range(req)
        names = {h["mac"]: (h.get("netwatch_name") or h.get("hostname"))
                 for h in (engine.box.hosts() or []) if h.get("mac")}
        out = wifi.report(db, start, now, names, now)
        out["radios"] = engine.box.radios
        out["recommendations"] = engine.box.status()["wifi"]["recommendations"]
        return JSONResponse(out)

    async def box_wifi_device(req: Request):
        from . import wifi
        mac = req.path_params["mac"].lower()
        if len(mac) != 17:
            return JSONResponse({"error": "adresse MAC invalide"}, 400)
        start, now, step, _src = _range(req)
        return JSONResponse({**wifi.device_detail(db, mac, start, now, step), "start": start, "end": now,
                             "step": step})

    async def air_get(_: Request):
        radios = (engine.box.radios or {}).get("bands") or {}
        wifi_ch = (radios.get("2.4") or {}).get("channel")
        zb_ch = ((engine.z2m.info or {}).get("channel"))
        return JSONResponse(airscan.analyze(airscan.last(db), wifi_ch, zb_ch))

    async def air_ingest(req: Request):
        body = await req.body()
        if len(body) > 1_000_000:
            return JSONResponse({"error": "corps trop volumineux"}, 413)
        try:
            d = json.loads(body)
            snap = airscan.ingest(db, str(d.get("scan") or ""), str(d.get("iface") or ""), str(d.get("host") or ""))
        except (ValueError, AttributeError) as e:
            return JSONResponse({"error": str(e)}, 400)
        return JSONResponse({"ok": True, "aps": len(snap["aps"])})

    async def air_token(req: Request):
        regen = req.method == "POST"
        return JSONResponse({"token": airscan.token(db, regenerate=regen)})

    async def index(_: Request):
        return FileResponse(os.path.join(WEB_DIR, "index.html"), headers={"Cache-Control": "no-cache"})

    async def service_worker(_: Request):
        # servi à la racine pour contrôler tout le scope de l'app
        return FileResponse(os.path.join(WEB_DIR, "sw.js"),
                            headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"},
                            media_type="application/javascript")

    async def manifest(_: Request):
        return FileResponse(os.path.join(WEB_DIR, "manifest.webmanifest"),
                            media_type="application/manifest+json")

    # ------------------------------------------------------------ authentification
    async def session_info(req: Request):
        if auth.open_mode:
            return JSONResponse({"auth_required": False, "authenticated": True,
                                 "setup_required": False, "username": None,
                                 "wizard_required": db.get_meta("wizard_done") != "1"})
        if auth.setup_required:
            return JSONResponse({"auth_required": True, "authenticated": False,
                                 "setup_required": True, "username_default": cfg.username})
        user = auth.validate_session(req.cookies.get("nw_session"))
        return JSONResponse({"auth_required": True, "authenticated": bool(user),
                             "setup_required": False, "username": user,
                             "wizard_required": bool(user) and db.get_meta("wizard_done") != "1",
                             "passkeys": webauthn.available and webauthn.has_credentials()})

    async def setup(req: Request):
        if auth.open_mode:
            return JSONResponse({"error": "authentification désactivée (NETWATCH_NO_AUTH)"}, 400)
        if auth.enabled:
            return JSONResponse({"error": "authentification déjà configurée"}, 409)
        # le compte administrateur ne se crée que depuis le réseau local, jamais depuis Internet
        with contextlib.suppress(ValueError):
            addr = ipaddress.ip_address(client_ip(req))
            if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                return JSONResponse({"error": "la création du compte se fait depuis le réseau local"}, 403)
        body = await _json(req)
        ok, err = auth.initial_setup(str(body.get("username", "")), str(body.get("password", "")))
        if not ok:
            return JSONResponse({"error": err}, 400)
        token, _ = auth.create_session(client_ip(req))
        resp = JSONResponse({"ok": True, "username": auth.username})
        set_session_cookie(resp, req, token)
        return resp

    async def login(req: Request):
        ip = client_ip(req)
        lock = auth.locked_for(ip)
        if lock:
            return JSONResponse({"error": f"Trop de tentatives. Réessaie dans {lock} s."}, 429)
        body = {}
        with contextlib.suppress(Exception):
            body = await req.json()
        if not auth.enabled:
            return JSONResponse({"error": "authentification non configurée"}, 400)
        if not auth.check_credentials(str(body.get("username", "")), str(body.get("password", ""))):
            auth.record_failure(ip)
            return JSONResponse({"error": "Identifiant ou mot de passe incorrect."}, 401)
        auth.record_success(ip)
        auth.purge_sessions()
        token, _ = auth.create_session(ip)
        resp = JSONResponse({"authenticated": True, "username": auth.username})
        set_session_cookie(resp, req, token)
        return resp

    async def logout(req: Request):
        auth.destroy_session(req.cookies.get("nw_session"))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie("nw_session", path="/")
        return resp

    async def password_change(req: Request):
        if not auth.enabled:
            return JSONResponse({"error": "authentification désactivée"}, 400)
        ip = client_ip(req)
        if auth.locked_for(ip):
            return JSONResponse({"error": "Trop de tentatives. Réessaie plus tard."}, 429)
        body = await _json(req)
        ok, err = auth.set_password(str(body.get("current", "")), str(body.get("new", "")))
        if not ok:
            if "incorrect" in (err or ""):
                auth.record_failure(ip)     # une session volée ne doit pas servir à deviner le mot de passe
            return JSONResponse({"error": err}, 400)
        # le changement invalide toutes les sessions : on en recrée une pour rester connecté ici
        token, _ = auth.create_session(client_ip(req))
        resp = JSONResponse({"ok": True})
        set_session_cookie(resp, req, token)
        return resp

    # ------------------------------------------------------------ garde d'accès (ASGI pur, compatible SSE)
    PUBLIC = {"/api/health", "/api/session", "/api/login", "/api/setup", "/",
              "/index.html", "/sw.js", "/manifest.webmanifest",
              "/api/webauthn/auth/options", "/api/webauthn/auth/verify"}

    class AuthGuard:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http" or auth.open_mode:
                return await self.app(scope, receive, send)
            path = scope["path"]
            if path in PUBLIC or path.startswith("/static/"):
                return await self.app(scope, receive, send)
            # dépôt du scan Wi-Fi par l'agent : jeton dédié, uniquement cette route
            if path == "/api/air/ingest" and scope["method"] == "POST":
                tok = dict(scope.get("headers") or []).get(b"x-netwatch-token", b"").decode("latin-1")
                if airscan.token_ok(db, tok):
                    return await self.app(scope, receive, send)
            # tant que le compte n'est pas créé, l'API reste fermée (sauf routes publiques)
            if auth.setup_required:
                resp = JSONResponse({"error": "configuration initiale requise", "setup_required": True}, 401)
                return await resp(scope, receive, send)
            headers = dict(scope.get("headers") or [])
            cookies = _parse_cookies(headers.get(b"cookie", b"").decode("latin-1"))
            if auth.validate_session(cookies.get("nw_session")):
                return await self.app(scope, receive, send)
            # repli : auth Basic pour les scripts / l'API, avec la même limitation des tentatives
            h = headers.get(b"authorization", b"").decode("latin-1")
            if h.lower().startswith("basic ") and len(h) < 2048:
                client = scope.get("client")
                ip = peer_ip(client[0] if client else "?", headers.get(b"x-forwarded-for", b"").decode("latin-1"))
                if auth.locked_for(ip):
                    resp = JSONResponse({"error": "trop de tentatives"}, 429)
                    return await resp(scope, receive, send)
                try:
                    user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
                    ok = await asyncio.to_thread(auth.check_basic, h, user, pw)
                except Exception:  # noqa: BLE001
                    ok = False
                if ok:
                    return await self.app(scope, receive, send)
                auth.record_failure(ip)
            resp = JSONResponse({"error": "authentification requise"}, 401)
            return await resp(scope, receive, send)

    # ------------------------------------------------------------ durcissement HTTP (ASGI pur)
    SECURITY_HEADERS = [
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
        (b"cross-origin-opener-policy", b"same-origin"),
        (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
        # scripts : uniquement les fichiers de l'application (aucun script en ligne) ; les styles en
        # ligne restent permis, l'interface en utilise.
        (b"content-security-policy",
         b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
         b"connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
    ]
    # intégration dans un cadre (tableau de bord domotique…) : interdite sauf pour les sites listés
    ancestors = " ".join(a for a in cfg.frame_ancestors.replace(",", " ").split()
                         if a.startswith(("https://", "http://")) and not any(c in a for c in ";'\""))
    sec_headers = [(k, v.replace(b"frame-ancestors 'none'", b"frame-ancestors 'self' " + ancestors.encode())
                    if ancestors else v) for k, v in SECURITY_HEADERS if not (ancestors and k == b"x-frame-options")]
    MAX_BODY = 1_048_576       # 1 Mo : aucune requête légitime n'approche cette taille
    UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}

    class Hardening:
        """En-têtes de sécurité, taille de requête bornée, et refus des écritures venant d'un autre site."""

        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                return await self.app(scope, receive, send)
            headers = dict(scope.get("headers") or [])

            async def send_wrapped(message):
                if message["type"] == "http.response.start":
                    message = {**message, "headers": [*message.get("headers", []), *sec_headers]}
                await send(message)

            if scope["method"] in UNSAFE:
                # écriture déclenchée par une page d'un autre site : refusée. Sec-Fetch-Site est posé
                # par le navigateur et ne peut pas être falsifié par la page (le cookie est déjà SameSite=Strict).
                if headers.get(b"sec-fetch-site", b"").decode("latin-1").lower() == "cross-site":
                    resp = JSONResponse({"error": "origine refusée"}, 403)
                    return await resp(scope, receive, send_wrapped)
                try:
                    declared = int(headers.get(b"content-length", b"0") or 0)
                except ValueError:
                    declared = MAX_BODY + 1
                if declared > MAX_BODY:
                    resp = JSONResponse({"error": "requête trop volumineuse"}, 413)
                    return await resp(scope, receive, send_wrapped)
                seen = 0

                async def limited_receive():
                    nonlocal seen
                    message = await receive()
                    if message["type"] == "http.request":
                        seen += len(message.get("body", b""))
                        if seen > MAX_BODY:       # corps annoncé plus petit qu'il ne l'est (ou envoi par morceaux)
                            return {"type": "http.disconnect"}
                    return message
                return await self.app(scope, limited_receive, send_wrapped)
            return await self.app(scope, receive, send_wrapped)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        await engine.start()
        try:
            yield
        finally:
            await engine.stop()

    routes = [
        Route("/api/health", health),
        Route("/api/overview", overview),
        Route("/api/metrics/overview", overview_metrics),
        Route("/api/devices", devices),
        Route("/api/devices/{id:int}", device, methods=["GET"]),
        Route("/api/devices/{id:int}", device_patch, methods=["PATCH"]),
        Route("/api/devices/{id:int}", device_delete, methods=["DELETE"]),
        Route("/api/devices/{id:int}/metrics", device_metrics),
        Route("/api/devices/{id:int}/scan", device_scan, methods=["POST"]),
        Route("/api/heatmap", heatmap),
        Route("/api/events", events),
        Route("/api/scans", scans),
        Route("/api/scan/{kind}", scan_now, methods=["POST"]),
        Route("/api/credentials", creds_list, methods=["GET"]),
        Route("/api/credentials", creds_create, methods=["POST"]),
        Route("/api/credentials/{id:int}", creds_update, methods=["PATCH"]),
        Route("/api/credentials/{id:int}", creds_delete, methods=["DELETE"]),
        Route("/api/credentials/{id:int}/test", creds_test, methods=["POST"]),
        Route("/api/settings", settings_get),
        Route("/api/settings", settings_patch, methods=["PATCH"]),
        Route("/api/box", box_status),
        Route("/api/box/refresh", box_refresh, methods=["POST"]),
        Route("/api/box/detect", box_detect, methods=["POST"]),
        Route("/api/box/test", box_test, methods=["POST"]),
        Route("/api/box/usage", box_usage),
        Route("/api/box/provider", box_provider_set, methods=["PUT"]),
        Route("/api/box/credentials", box_credentials_set, methods=["PUT"]),
        Route("/api/box/credentials", box_credentials_delete, methods=["DELETE"]),
        Route("/api/box/approval", box_approval_start, methods=["POST"]),
        Route("/api/box/approval", box_approval_status),
        Route("/api/box/wifi", box_wifi),
        Route("/api/box/wifi/{mac}", box_wifi_device),
        Route("/api/wizard", wizard_get),
        Route("/api/wizard/complete", wizard_complete, methods=["POST"]),
        Route("/api/wizard/reset", wizard_reset, methods=["POST"]),
        Route("/api/z2m", z2m_status),
        Route("/api/z2m/report", z2m_report),
        Route("/api/z2m/test", z2m_test, methods=["POST"]),
        Route("/api/z2m/networkmap", z2m_networkmap, methods=["POST"]),
        Route("/api/z2m/import", z2m_import, methods=["POST"]),
        Route("/api/z2m/mqtt-password", mqtt_password_set, methods=["PUT"]),
        Route("/api/z2m/mqtt-password", mqtt_password_delete, methods=["DELETE"]),
        Route("/api/z2m/ha-token", ha_token_set, methods=["PUT"]),
        Route("/api/z2m/ha-token", ha_token_delete, methods=["DELETE"]),
        Route("/api/air", air_get),
        Route("/api/air/ingest", air_ingest, methods=["POST"]),
        Route("/api/air/token", air_token, methods=["GET", "POST"]),
        Route("/api/conflicts", conflicts),
        Route("/api/findings", findings),
        Route("/api/diagnostics", diag_runs),
        Route("/api/diagnostics/{id:int}", diag_run_get),
        Route("/api/diagnostics", diag_start, methods=["POST"]),
        Route("/api/push/config", push_config),
        Route("/api/push/subscribe", push_subscribe, methods=["POST"]),
        Route("/api/push/subscribe", push_update, methods=["PATCH"]),
        Route("/api/push/unsubscribe", push_unsubscribe, methods=["POST"]),
        Route("/api/push/test", push_test, methods=["POST"]),
        Route("/api/webauthn/register/options", wa_register_options, methods=["POST"]),
        Route("/api/webauthn/register/verify", wa_register_verify, methods=["POST"]),
        Route("/api/webauthn/auth/options", wa_auth_options, methods=["POST"]),
        Route("/api/webauthn/auth/verify", wa_auth_verify, methods=["POST"]),
        Route("/api/webauthn/credentials", wa_list, methods=["GET"]),
        Route("/api/webauthn/credentials/{id:int}", wa_delete, methods=["DELETE"]),
        Route("/api/stream", stream),
        Route("/api/session", session_info),
        Route("/api/setup", setup, methods=["POST"]),
        Route("/api/login", login, methods=["POST"]),
        Route("/api/logout", logout, methods=["POST"]),
        Route("/api/password", password_change, methods=["POST"]),
        Route("/", index),
        Route("/sw.js", service_worker),
        Route("/manifest.webmanifest", manifest),
        Mount("/static", StaticFiles(directory=WEB_DIR), name="static"),
    ]
    return Starlette(routes=routes, middleware=[Middleware(Hardening), Middleware(AuthGuard)], lifespan=lifespan)
