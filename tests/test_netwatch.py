"""Tests (stdlib unittest) : python -m unittest discover -s tests -v"""
import asyncio
import json
import os
import socket
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import arp, icmp, names, nmapscan, notify  # noqa: E402
from app.config import Config  # noqa: E402
from app.db import DB  # noqa: E402
from app.netutil import is_random_mac, normalize_mac  # noqa: E402

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<address addr="BC:24:11:4E:00:10" addrtype="mac" vendor="Proxmox Server Solutions"/>
<hostnames><hostname name="proxmox.home" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1" extrainfo="Debian"/></port>
<port protocol="tcp" portid="8006"><state state="open"/><service name="https" product="Proxmox VE"/></port>
<port protocol="tcp" portid="25"><state state="closed"/><service name="smtp"/></port>
</ports>
<os><osmatch name="Linux 5.0 - 5.14" accuracy="95"/><osmatch name="Linux 6.1" accuracy="98"/></os>
</host>
<host><status state="down"/><address addr="192.168.1.99" addrtype="ipv4"/></host>
</nmaprun>"""


class ParsersTest(unittest.TestCase):
    def test_nmap_xml(self):
        r = nmapscan.parse_nmap_xml(NMAP_XML)
        self.assertEqual(list(r), ["192.168.1.10"])
        h = r["192.168.1.10"]
        self.assertEqual([p["port"] for p in h["ports"]], [22, 8006])
        self.assertEqual(h["os"], ("Linux 6.1", 98))
        self.assertEqual(h["hostname"], "proxmox.home")
        self.assertEqual(h["mac"], "bc:24:11:4e:00:10")
        self.assertEqual(nmapscan.parse_nmap_xml("pas du xml"), {})

    def test_arp_roundtrip(self):
        req = arp.build_request(b"\x02\x00\x00\x00\x00\x01", "192.168.1.2", "192.168.1.1")
        self.assertEqual(len(req), 42)
        self.assertIsNone(arp.parse_reply(req))  # une requête n'est pas une réponse
        reply = bytearray(req)
        reply[20:22] = struct.pack("!H", 2)
        reply[22:28] = bytes.fromhex("aabbccddeeff")
        reply[28:32] = socket.inet_aton("192.168.1.1")
        self.assertEqual(arp.parse_reply(bytes(reply)), ("192.168.1.1", "aa:bb:cc:dd:ee:ff"))

    def test_icmp(self):
        pkt = icmp.build_echo(0x1234, 7, 0xDEADBEEF)
        self.assertEqual(icmp.checksum(pkt), 0)  # somme de contrôle valide
        reply = bytearray(pkt)
        reply[0] = 0
        self.assertEqual(icmp.parse_reply(bytes(reply), raw=False), (0x1234, 7, 0xDEADBEEF))
        self.assertEqual(icmp.parse_reply(b"\x45" + b"\x00" * 19 + bytes(reply), raw=True), (0x1234, 7, 0xDEADBEEF))
        self.assertIsNone(icmp.parse_reply(pkt, raw=False))  # echo-request ignoré

    def test_ping_localhost(self):
        r = icmp.multiping(["127.0.0.1"], count=2, timeout=0.5)
        self.assertEqual(r["127.0.0.1"]["recv"], 2)

    def test_dns_ptr(self):
        q = names.build_ptr_query("192.168.1.20", qid=1)
        # réponse : en-tête + question recopiée + 1 réponse PTR compressée
        question = q[12:]
        hdr = struct.pack("!HHHHHH", 1, 0x8400, 1, 1, 0, 0)
        rdata = names.encode_name("pc-bureau.local")
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
        self.assertEqual(names.parse_ptr_response(hdr + question + ans), "pc-bureau.local")

    def test_netbios(self):
        q = names.build_nbstat_query(qid=5)
        self.assertEqual(len(q), 50)
        name = b"\x20" + b"CK" + b"AA" * 15 + b"\x00"
        entries = b"PC-BUREAU".ljust(15) + b"\x00" + struct.pack("!H", 0x0400)
        entries += b"WORKGROUP".ljust(15) + b"\x00" + struct.pack("!H", 0x8400)
        rdata = bytes([2]) + entries
        resp = struct.pack("!HHHHHH", 5, 0x8400, 0, 1, 0, 0) + name + struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata
        self.assertEqual(names.parse_nbstat_response(resp), "PC-BUREAU")

    def test_best_name(self):
        self.assertEqual(names.best_name({"mdns": "a", "netbios": "B"}), ("a", "mdns"))
        self.assertEqual(names.best_name({"dns": "nas.home"}), ("nas", "dns"))
        self.assertTrue(names._is_junk("192-168-1-5.home", "192.168.1.5"))
        self.assertEqual(names.clean('evil"<script>'), "evilscript")

    def test_exclude(self):
        from app.netutil import NetInfo, ip_in_nets, parse_nets
        nets = parse_nets(["192.168.1.50", "10.0.0.0/8", "pas-une-ip"])
        self.assertEqual(len(nets), 2)  # l'entrée invalide est ignorée
        self.assertTrue(ip_in_nets("192.168.1.50", nets))
        self.assertTrue(ip_in_nets("10.1.2.3", nets))
        self.assertFalse(ip_in_nets("192.168.1.51", nets))
        net = NetInfo(subnet="192.168.1.0/29", exclude=["192.168.1.2", "192.168.1.4"])
        hosts = net.hosts()
        self.assertNotIn("192.168.1.2", hosts)
        self.assertNotIn("192.168.1.4", hosts)
        self.assertIn("192.168.1.3", hosts)
        self.assertTrue(net.is_excluded("192.168.1.2"))
        self.assertIn("192.168.1.2/32", net.as_dict()["excluded"])

    def test_mac(self):
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertTrue(is_random_mac("5a:1e:22:9b:7c:30"))
        self.assertFalse(is_random_mac("bc:24:11:4e:00:10"))

    def test_mqtt_packets(self):
        self.assertEqual(notify._remaining_length(127), b"\x7f")
        self.assertEqual(notify._remaining_length(321), b"\xc1\x02")
        p = notify.mqtt_publish_packet("a/b", b"x" * 200)
        self.assertEqual(p[0], 0x30)
        c = notify.mqtt_connect_packet("id", "u", "p")
        self.assertEqual(c[0], 0x10)


class FakeBackend:
    def __init__(self):
        self.hosts = {}
        self.ports = {}

    async def discover(self):
        return {ip: (mac, 0.5) for ip, mac in self.hosts.items()}

    async def ping(self, ips):
        return {ip: {"sent": 3, "recv": 3, "loss": 0.0, "avg": 1.5, "min": 1, "max": 2} for ip in ips}

    async def resolve(self, ip):
        return {"dns": f"host-{ip.split('.')[-1]}.lan"}

    async def deep_scan(self, ip):
        return {"ports": self.ports.get(ip, []), "os": ("Linux", 90), "hostname": None, "mac": None, "vendor": None}


def port(n):
    return {"port": n, "proto": "tcp", "service": "x", "product": None, "version": None, "extra": None}


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["NETWATCH_DATA_DIR"] = self.tmp

    def run_async(self, coro):
        return asyncio.run(coro)

    def make(self):
        from app.engine import Engine

        cfg = Config()
        cfg.external_targets = ["1.1.1.1"]
        cfg.offline_after = 2
        db = DB(os.path.join(self.tmp, "t.db"))
        eng = Engine(cfg, db)
        eng.backend = FakeBackend()
        eng.net.ip = eng.net.mac = None
        eng._ensure_external_targets()
        return eng, db

    def test_lifecycle(self):
        async def scenario():
            eng, db = self.make()
            b = eng.backend
            b.hosts = {"192.168.1.1": "aa:aa:aa:aa:aa:01", "192.168.1.2": "aa:aa:aa:aa:aa:02"}
            await eng.discovery_cycle()
            ev = [e["type"] for e in db.q("SELECT type FROM events ORDER BY id")]
            self.assertEqual(ev.count("new_device"), 2)
            self.assertIn("inventory", ev)
            self.assertEqual(db.q1("SELECT COUNT(*) n FROM devices WHERE kind='lan' AND online=1")["n"], 2)

            # nouveau venu + changement d'IP
            b.hosts = {"192.168.1.1": "aa:aa:aa:aa:aa:01", "192.168.1.3": "aa:aa:aa:aa:aa:02",
                       "192.168.1.50": "5a:00:00:00:00:50"}
            await eng.discovery_cycle()
            new = db.q1("SELECT * FROM devices WHERE mac='5a:00:00:00:00:50'")
            self.assertEqual(new["random_mac"], 1)
            self.assertTrue(db.q1("SELECT 1 FROM events WHERE type='ip_changed'"))
            self.assertIn(new["id"], eng.deep_pending)  # scan nmap auto pour le nouveau

            # disparition : hors ligne après 2 cycles manqués
            b.hosts = {"192.168.1.1": "aa:aa:aa:aa:aa:01"}
            await eng.discovery_cycle()
            self.assertEqual(db.q1("SELECT online FROM devices WHERE id=?", [new["id"]])["online"], 1)
            await eng.discovery_cycle()
            self.assertEqual(db.q1("SELECT online FROM devices WHERE id=?", [new["id"]])["online"], 0)
            self.assertTrue(db.q1("SELECT 1 FROM events WHERE type='device_offline' AND device_id=?", [new["id"]]))

            # résolution de noms
            await asyncio.sleep(0.05)
            self.assertEqual(db.q1("SELECT hostname FROM devices WHERE ip='192.168.1.1'")["hostname"], "host-1")

            # ports : premier scan silencieux, puis diff
            gw = db.q1("SELECT id FROM devices WHERE ip='192.168.1.1'")["id"]
            b.ports["192.168.1.1"] = [port(22), port(80)]
            await eng._deep_one(gw, None)
            self.assertFalse(db.q1("SELECT 1 FROM events WHERE type='port_opened'"))
            b.ports["192.168.1.1"] = [port(22), port(443)]
            await eng._deep_one(gw, None)
            self.assertTrue(db.q1("SELECT 1 FROM events WHERE type='port_opened' AND message LIKE '%443%'"))
            self.assertTrue(db.q1("SELECT 1 FROM events WHERE type='port_closed' AND message LIKE '%80/tcp%'"))
            self.assertEqual(db.q1("SELECT COUNT(*) n FROM ports WHERE device_id=? AND open=1", [gw])["n"], 2)

            # agrégation horaire
            db.x("UPDATE samples SET ts = ts - 7200")
            db.rollup_hourly()
            self.assertGreater(db.q1("SELECT COUNT(*) n FROM samples_hourly")["n"], 0)

        self.run_async(scenario())

    def test_exclude_device(self):
        async def scenario():
            eng, db = self.make()
            b = eng.backend
            b.hosts = {"192.168.1.1": "aa:aa:aa:aa:aa:01", "192.168.1.2": "aa:aa:aa:aa:aa:02"}
            await eng.discovery_cycle()
            d2 = db.q1("SELECT id FROM devices WHERE ip='192.168.1.2'")["id"]
            db.update("devices", d2, {"excluded": 1})
            eng._refresh_excluded()
            self.assertIn("192.168.1.2", eng.net.extra_excluded)
            self.assertTrue(eng.net.is_excluded("192.168.1.2"))

            # l'appareil exclu qui disparaît passe hors ligne sans alerte
            b.hosts = {"192.168.1.1": "aa:aa:aa:aa:aa:01"}
            for _ in range(3):
                await eng.discovery_cycle()
            self.assertFalse(db.q1("SELECT 1 FROM events WHERE type='device_offline' AND device_id=?", [d2]))
            self.assertEqual(db.q1("SELECT online FROM devices WHERE id=?", [d2])["online"], 0)
            # aucun scan nmap pour un exclu
            await eng._deep_one(d2, None)
            self.assertIsNone(db.q1("SELECT last_deep_scan FROM devices WHERE id=?", [d2])["last_deep_scan"])

        self.run_async(scenario())


try:
    import httpx  # requis par starlette.testclient
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


@unittest.skipUnless(_HAS_HTTPX, "httpx requis pour le client de test Starlette")
class ApiTest(unittest.TestCase):
    def test_endpoints_and_auth(self):
        from starlette.testclient import TestClient

        from app.api import create_app
        from app.engine import Engine

        tmp = tempfile.mkdtemp()
        cfg = Config()
        cfg.demo = True
        cfg.password = "secret"
        cfg.discovery_interval = 3600
        db = DB(os.path.join(tmp, "a.db"))
        eng = Engine(cfg, db)
        app = create_app(cfg, db, eng)
        with TestClient(app) as c:
            self.assertEqual(c.get("/api/health").status_code, 200)
            self.assertEqual(c.get("/api/overview").status_code, 401)
            c.auth = ("admin", "secret")
            o = c.get("/api/overview").json()
            self.assertGreater(o["devices"]["total"], 10)
            devs = c.get("/api/devices").json()
            did = devs[0]["id"]
            for path in ("metrics/overview?range=24h", "metrics/overview?range=30d", "heatmap?range=7d",
                         f"devices/{did}", f"devices/{did}/metrics?range=1h", "events", "scans"):
                r = c.get(f"/api/{path}")
                self.assertEqual(r.status_code, 200, path)
            r = c.patch(f"/api/devices/{did}", json={"alias": "Ma box", "watch": True, "hack": 1})
            self.assertEqual(r.json()["name"], "Ma box")
            self.assertEqual(c.get("/").status_code, 200)
            self.assertEqual(c.get("/static/app.js").status_code, 200)
            # V2 : endpoints présents
            for path in ("credentials", "conflicts", "findings", "diagnostics"):
                self.assertEqual(c.get(f"/api/{path}").status_code, 200, path)
            self.assertIn("ssh", o)
            self.assertIn("findings", o)

            # authentification par session (cookie)
            c.auth = None
            s = c.get("/api/session").json()
            self.assertTrue(s["auth_required"])
            self.assertFalse(s["authenticated"])
            self.assertEqual(c.get("/api/overview").status_code, 401)
            self.assertEqual(c.post("/api/login", json={"username": "admin", "password": "faux"}).status_code, 401)
            self.assertEqual(c.post("/api/login", json={"username": "admin", "password": "secret"}).status_code, 200)
            self.assertTrue(c.get("/api/session").json()["authenticated"])
            self.assertEqual(c.get("/api/overview").status_code, 200)  # via cookie
            c.post("/api/logout")
            self.assertEqual(c.get("/api/overview").status_code, 401)  # cookie effacé

    def test_setup_flow(self):
        from starlette.testclient import TestClient

        from app.api import create_app
        from app.engine import Engine

        tmp = tempfile.mkdtemp()
        cfg = Config()
        cfg.demo = True
        cfg.password = None          # aucun mot de passe → configuration initiale
        cfg.discovery_interval = 3600
        db = DB(os.path.join(tmp, "s.db"))
        app = create_app(cfg, db, Engine(cfg, db))
        with TestClient(app) as c:
            s = c.get("/api/session").json()
            self.assertTrue(s["setup_required"])
            self.assertEqual(c.get("/api/overview").status_code, 401)  # API fermée avant config
            self.assertEqual(c.post("/api/setup", json={"username": "chef", "password": "court"}).status_code, 400)
            self.assertEqual(c.post("/api/setup", json={"username": "chef", "password": "monmotdepasse"}).status_code, 200)
            self.assertFalse(c.get("/api/session").json()["setup_required"])
            self.assertEqual(c.get("/api/overview").status_code, 200)  # connecté via cookie
            self.assertEqual(c.post("/api/setup", json={"username": "x", "password": "autremotdepasse"}).status_code, 409)


class VaultTest(unittest.TestCase):
    def make(self):
        from app.vault import Vault
        db = DB(":memory:")
        return Vault(db, "clé-de-test-longue", "/tmp/nw-unused.key"), db

    def test_roundtrip_and_scope(self):
        from app.vault import in_scope, parse_scope
        v, _ = self.make()
        self.assertFalse(v.locked)
        token = v.encrypt("motdepasse")
        self.assertNotIn("motdepasse", token)
        self.assertEqual(v.decrypt(token), "motdepasse")
        self.assertEqual(parse_scope("192.168.1.0/24, 10.0.0.0/8"), ["192.168.1.0/24", "10.0.0.0/8"])
        self.assertTrue(in_scope("192.168.1.5", ["192.168.1.0/24"]))
        self.assertFalse(in_scope("10.0.0.1", ["192.168.1.0/24"]))
        self.assertTrue(in_scope("1.2.3.4", []))  # portée vide = tout

    def test_crud_and_candidates(self):
        v, db = self.make()
        c = v.create({"name": "root", "username": "root", "secret": "pw", "scope": "192.168.1.0/24", "priority": 10})
        self.assertTrue(c["has_secret"])
        self.assertNotIn("secret", c)
        v.create({"name": "admin", "username": "admin", "secret": "pw2", "priority": 50})
        cands = v.candidates("192.168.1.9", None)
        self.assertEqual([x["name"] for x in cands], ["root", "admin"])  # tri par priorité
        self.assertEqual([x["name"] for x in v.candidates("10.0.0.9", None)], ["admin"])  # hors portée
        row = db.q1("SELECT * FROM credentials WHERE id=?", [c["id"]])
        self.assertEqual(v.secrets_for(row)[0], "pw")
        with self.assertRaises(ValueError):
            v.create({"name": "x", "username": "bad user", "secret": "p"})

    def test_locked_after_key_change(self):
        from app.vault import Vault
        db = DB(":memory:")
        Vault(db, "clé-A", "/tmp/x.key").create({"name": "n", "username": "u", "secret": "s"})
        v2 = Vault(db, "clé-B", "/tmp/x.key")  # même base, clé différente
        self.assertTrue(v2.locked)


class AuthTest(unittest.TestCase):
    def test_hash_and_verify(self):
        from app import auth
        h = auth.hash_password("s3cret!")
        self.assertTrue(h.startswith("scrypt$"))
        self.assertNotIn("s3cret!", h)
        self.assertTrue(auth.verify_password("s3cret!", h))
        self.assertFalse(auth.verify_password("mauvais", h))
        self.assertFalse(auth.verify_password("x", None))

    def make(self, password="motdepasse", **over):
        cfg = Config()
        cfg.password = password
        for k, v in over.items():
            setattr(cfg, k, v)
        db = DB(":memory:")
        from app.auth import Auth
        return Auth(cfg, db), db

    def test_bootstrap_and_sessions(self):
        a, db = self.make()
        self.assertTrue(a.enabled)
        self.assertFalse(a.check_credentials("admin", "faux"))
        self.assertTrue(a.check_credentials("admin", "motdepasse"))
        self.assertFalse(a.check_credentials("root", "motdepasse"))  # mauvais utilisateur
        token, exp = a.create_session("1.2.3.4")
        self.assertEqual(a.validate_session(token), "admin")
        a.destroy_session(token)
        self.assertIsNone(a.validate_session(token))
        self.assertIsNone(a.validate_session("inexistant"))

    def test_password_change_invalidates_sessions(self):
        a, db = self.make()
        tok, _ = a.create_session("ip")
        ok, err = a.set_password("faux", "nouveaumdp12")
        self.assertFalse(ok)
        ok, err = a.set_password("motdepasse", "court")
        self.assertFalse(ok)  # trop court
        ok, err = a.set_password("motdepasse", "nouveaumdp12")
        self.assertTrue(ok, err)
        self.assertIsNone(a.validate_session(tok))  # sessions invalidées
        self.assertTrue(a.check_credentials("admin", "nouveaumdp12"))

    def test_rate_limit(self):
        a, _ = self.make()
        for _ in range(auth_max()):
            a.record_failure("9.9.9.9")
        self.assertGreater(a.locked_for("9.9.9.9"), 0)
        self.assertEqual(a.locked_for("8.8.8.8"), 0)

    def test_disabled_without_password(self):
        a, _ = self.make(password=None)
        self.assertFalse(a.enabled)

    def test_first_run_setup(self):
        a, _ = self.make(password=None)
        self.assertTrue(a.setup_required)
        self.assertFalse(a.open_mode)
        ok, err = a.initial_setup("chef", "court")
        self.assertFalse(ok)  # trop court
        ok, err = a.initial_setup("chef", "monmotdepasse")
        self.assertTrue(ok, err)
        self.assertTrue(a.enabled)
        self.assertFalse(a.setup_required)
        self.assertEqual(a.username, "chef")
        self.assertTrue(a.check_credentials("chef", "monmotdepasse"))
        ok, err = a.initial_setup("autre", "encoreunmdp")  # refusé si déjà configuré
        self.assertFalse(ok)

    def test_open_mode(self):
        a, _ = self.make(password=None, no_auth=True)
        self.assertTrue(a.open_mode)
        self.assertFalse(a.setup_required)


def auth_max():
    from app import auth
    return auth.LOGIN_MAX_FAILS


class PushTest(unittest.TestCase):
    def test_pure_helpers(self):
        from app import push
        self.assertEqual(push.sanitize_types(["new_device", "inconnu", "ip_conflict"]),
                         ["new_device", "ip_conflict"])
        self.assertEqual(push.sanitize_types("pas une liste"), push.DEFAULT_TYPES)
        p = push.build_payload({"type": "device_offline", "message": "X hors ligne", "severity": "warning"},
                               {"id": 7})
        self.assertIn("hors ligne", p["body"])
        self.assertEqual(p["url"], "/#/device/7")
        self.assertEqual(p["tag"], "device_offline:7")
        self.assertIn("Android", push.ua_label("Mozilla/5.0 (Linux; Android 14) Chrome/120"))

    def test_subscription_crud(self):
        from app.push import PushManager
        db = DB(":memory:")
        cfg = Config()
        pm = PushManager(cfg, db)
        self.assertTrue(pm.available)                       # clés VAPID générées
        self.assertTrue(pm.application_server_key)
        self.assertIsNotNone(pm._vapid)                     # objet Vapid prêt pour pywebpush
        sub = {"endpoint": "https://push.example/abc", "keys": {"p256dh": "k", "auth": "a"}}
        pm.subscribe(sub, ["new_device", "bad"], "Android Chrome")
        rows = pm.list()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["notify_types"], ["new_device"])
        self.assertFalse(rows[0]["last_ok"])
        pm.update(sub["endpoint"], notify_types=["ip_conflict"], enabled=False)
        r = pm.get(sub["endpoint"])
        self.assertEqual(r["notify_types"], ["ip_conflict"])
        self.assertFalse(r["enabled"])
        # send_event n'envoie qu'aux abonnements actifs souscrits au type (ici désactivé → 0)
        self.assertEqual(pm.send_event({"type": "ip_conflict", "message": "m", "severity": "critical"}, None), 0)
        pm.unsubscribe(sub["endpoint"])
        self.assertEqual(pm.list(), [])

    def test_vapid_key_stable(self):
        from app.push import PushManager
        db = DB(":memory:")
        cfg = Config()
        k1 = PushManager(cfg, db).application_server_key
        k2 = PushManager(cfg, db).application_server_key  # rechargée depuis la base
        self.assertEqual(k1, k2)


class SettingsTest(unittest.TestCase):
    def test_apply_and_load(self):
        from app import settings
        cfg = Config()
        db = DB(":memory:")
        r = settings.apply(cfg, db, {
            "discovery_interval": "120", "ping_timeout": "1.5", "ssh_enabled": False,
            "external_targets": "1.1.1.1, 9.9.9.9", "nmap_concurrency": "5", "inconnu": "x",
        })
        self.assertEqual(cfg.discovery_interval, 120)
        self.assertEqual(cfg.ping_timeout, 1.5)
        self.assertFalse(cfg.ssh_enabled)
        self.assertEqual(cfg.external_targets, ["1.1.1.1", "9.9.9.9"])
        self.assertIn("nmap_concurrency", r["restart_needed"])
        self.assertNotIn("inconnu", r["applied"])
        # rechargé depuis la base dans un nouveau Config
        cfg2 = Config()
        settings.load_overrides(cfg2, db)
        self.assertEqual(cfg2.discovery_interval, 120)
        self.assertEqual(cfg2.external_targets, ["1.1.1.1", "9.9.9.9"])
        self.assertFalse(cfg2.ssh_enabled)

    def test_invalid_value(self):
        from app import settings
        cfg = Config()
        db = DB(":memory:")
        r = settings.apply(cfg, db, {"discovery_interval": "abc"})
        self.assertIn("discovery_interval", r["errors"])
        self.assertNotIn("discovery_interval", r["applied"])

    def test_public_schema(self):
        from app import settings
        pub = settings.public(Config())
        self.assertTrue(pub["groups"])
        keys = [s["key"] for g in pub["groups"] for s in g["settings"]]
        self.assertIn("nmap_args", keys)


class HADiscoveryTest(unittest.TestCase):
    def test_config_messages(self):
        import json as _json

        from app.notify import Notifier
        cfg = Config()
        cfg.mqtt_host = "192.168.1.11"
        cfg.mqtt_discovery = True
        n = Notifier(cfg)
        d = {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.13", "hostname": "nas",
             "vendor": "Synology", "os_name": "Linux 4.4"}
        msgs = n.ha_config_messages(d)
        self.assertEqual(len(msgs), 2)
        topics = [m[0] for m in msgs]
        self.assertIn("homeassistant/binary_sensor/netwatch_aabbccddeeff/config", topics)
        self.assertIn("homeassistant/sensor/netwatch_aabbccddeeff_lat/config", topics)
        conn = _json.loads(msgs[0][1])
        self.assertEqual(conn["device_class"], "connectivity")
        self.assertEqual(conn["state_topic"], "netwatch/device/aabbccddeeff/state")
        self.assertEqual(conn["device"]["manufacturer"], "Synology")
        self.assertTrue(all(m[2] for m in msgs))  # retain=True


class DhcpTest(unittest.TestCase):
    def test_discover_and_parse(self):
        from app import dhcp
        pkt = dhcp.build_discover("aa:bb:cc:dd:ee:ff", xid=0x12345678)
        self.assertEqual(pkt[236:240], dhcp.MAGIC)
        self.assertEqual(pkt[0], 1)  # BOOTREQUEST
        # forge un OFFER en réponse
        offer = bytearray(240)
        offer[0] = 2  # BOOTREPLY
        struct.pack_into("!I", offer, 4, 0x12345678)  # xid
        offer[16:20] = socket.inet_aton("192.168.1.50")  # yiaddr
        offer[236:240] = dhcp.MAGIC
        offer += bytes([53, 1, 2])                       # type = OFFER
        offer += bytes([54, 4]) + socket.inet_aton("192.168.1.1")  # server id
        offer += bytes([255])
        r = dhcp.parse_offer(bytes(offer), xid=0x12345678)
        self.assertEqual(r["server_id"], "192.168.1.1")
        self.assertEqual(r["offered_ip"], "192.168.1.50")
        # mauvais xid -> ignoré ; paquet non-OFFER -> None
        self.assertIsNone(dhcp.parse_offer(bytes(offer), xid=1))
        self.assertIsNone(dhcp.parse_offer(b"\x00" * 300))


class SecurityTest(unittest.TestCase):
    def test_analyze(self):
        from app import security
        dev = {"id": 5, "ip": "192.168.1.5", "hostname": "nas", "dev_type": "nas"}
        ports = [
            {"port": 23, "proto": "tcp", "service": "telnet", "product": None, "version": None},
            {"port": 6379, "proto": "tcp", "service": "redis", "product": "Redis", "version": "6.2"},
            {"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH", "version": "7.4"},
            {"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH", "version": "6.6"},
        ]
        keys = {f["key"]: f for f in security.analyze(dev, ports)}
        self.assertIn("sec:5:risky:23", keys)                       # telnet
        self.assertEqual(keys["sec:5:risky:23"]["severity"], "critical")
        self.assertIn("sec:5:db:6379", keys)                        # redis exposé
        self.assertIn("sec:5:oldver:22", keys)                      # openssh 6.6 < 8.0
        self.assertTrue(all(f["category"] == "security" for f in keys.values()))

    def test_no_findings_for_clean_host(self):
        from app import security
        dev = {"id": 1, "ip": "192.168.1.1", "dev_type": "server"}
        ports = [{"port": 443, "proto": "tcp", "service": "https", "product": "nginx", "version": "1.24"}]
        self.assertEqual(security.analyze(dev, ports), [])


class WebAuthnTest(unittest.TestCase):
    def make(self):
        from app.webauthn_mgr import WebAuthnManager
        db = DB(":memory:")
        return WebAuthnManager(Config(), db), db

    def test_context_and_challenges(self):
        wam, _ = self.make()
        # rp_id déduit de l'origine (hôte sans schéma ni port)
        self.assertEqual(wam.rp_id("https://netwatch.example.com:12025"), "netwatch.example.com")
        self.assertEqual(wam.origin("https://netwatch.example.com:12025"), "https://netwatch.example.com:12025")
        cfg = Config(); cfg.rp_id = "forced.example"; cfg.rp_origin = "https://forced.example"
        from app.webauthn_mgr import WebAuthnManager
        wam2 = WebAuthnManager(cfg, DB(":memory:"))
        self.assertEqual(wam2.rp_id("https://autre.com:1"), "forced.example")
        self.assertEqual(wam2.origin("https://autre.com:1"), "https://forced.example")
        # défi : consommable une seule fois, filtré par usage
        cid = wam._new_challenge(b"abc", "auth")
        self.assertIsNone(wam._take_challenge(cid, "register"))  # mauvais usage
        self.assertEqual(wam._take_challenge(cid, "auth"), b"abc")
        self.assertIsNone(wam._take_challenge(cid, "auth"))      # déjà consommé

    def test_registration_options_and_listing(self):
        wam, db = self.make()
        self.assertFalse(wam.has_credentials())
        options_json, state = wam.begin_registration("admin", "https://netwatch.example.com:12025")
        self.assertIn("challenge", options_json)
        self.assertIn("netwatch.example.com", options_json)
        self.assertTrue(state)
        # insertion directe d'un credential pour vérifier la liste / suppression
        db.x("INSERT INTO webauthn_credentials(credential_id, public_key, sign_count, name, created) VALUES(?,?,?,?,?)",
             ["Y3JlZA", "cHVi", 0, "iPhone", 1])
        self.assertTrue(wam.has_credentials())
        self.assertEqual(wam.list()[0]["name"], "iPhone")
        self.assertIsNotNone(wam.begin_authentication("https://netwatch.example.com:12025"))
        wam.delete(wam.list()[0]["id"])
        self.assertFalse(wam.has_credentials())
        self.assertIsNone(wam.begin_authentication("https://netwatch.example.com:12025"))


class SSHParseTest(unittest.TestCase):
    SAMPLE = (
        "@@NW:uname\nLinux nas 6.1.0-amd64 x86_64\n"
        "@@NW:os_release\nPRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\nVERSION_ID=12\n"
        "@@NW:meminfo\nMemTotal: 8000000 kB\nMemAvailable: 4000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
        "@@NW:df\nFilesystem Type 1024-blocks Used Available Capacity Mounted on\n"
        "/dev/sda1 ext4 100000 40000 60000 40% /\n"
        "@@NW:links\neth0 1000 full up 1500 phys\nwlan0 - - down 1500 wifi\n"
        "@@NW:netdev\nInter-|   Receive\n face |bytes    packets errs drop\n"
        "  eth0: 1000 10 2 1 0 0 0 0 500 5 3 0 0 0 0 0\n"
        "@@NW:listen\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:445 0.0.0.0:*\n"
        "@@NW:uptime\n123456.7 100000.0\n"
        "@@NW:loadavg\n0.50 0.40 0.30 1/200 1234\n"
        "@@NW:end\n"
    )

    def test_parse_inventory(self):
        from app import sshscan
        inv = sshscan.parse_inventory(self.SAMPLE, collected_at=1000)
        self.assertEqual(inv["hostname"], "nas")
        self.assertEqual(inv["kernel"], "6.1.0-amd64")
        self.assertEqual(inv["os"]["id"], "debian")
        self.assertEqual(inv["memory"]["total"], 8000000 * 1024)
        self.assertEqual(inv["disks"][0]["mount"], "/")
        eth = next(i for i in inv["interfaces"] if i["name"] == "eth0")
        self.assertEqual(eth["speed"], 1000)
        self.assertEqual(eth["duplex"], "full")
        self.assertEqual(eth["rx_errs"], 2)
        self.assertEqual([p["port"] for p in inv["listening"]], [22, 445])
        self.assertEqual(inv["uptime_s"], 123456)

    def test_parse_helpers(self):
        from app import sshscan
        self.assertEqual(sshscan.parse_default_route("default via 192.168.1.1 dev eth0"), "192.168.1.1")
        neigh = sshscan.parse_neigh("192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE")
        self.assertEqual(neigh[0]["mac"], "aa:bb:cc:dd:ee:ff")
        tcp = sshscan.parse_snmp_tcp("Tcp: A OutSegs RetransSegs\nTcp: 1 1000 50")
        self.assertEqual(tcp["RetransSegs"], 50)


class DiagTest(unittest.TestCase):
    def test_traceroute_analysis(self):
        from app.diagnostics import traceroute_analysis
        hops = [{"ttl": 1, "avg": 1.0, "ip": "192.168.1.1"},
                {"ttl": 2, "avg": 3.0, "ip": "10.0.0.1"},
                {"ttl": 3, "avg": 45.0, "ip": "203.0.113.1"},
                {"ttl": 4, "avg": 48.0, "ip": "8.8.8.8"}]
        r = traceroute_analysis(hops, jump_ms=15)
        self.assertEqual(r["ttl"], 3)
        self.assertEqual(r["segment"], "fai")
        # pic isolé qui ne se propage pas → rien
        hops2 = [{"ttl": 1, "avg": 1.0}, {"ttl": 2, "avg": 90.0}, {"ttl": 3, "avg": 2.0}]
        self.assertIsNone(traceroute_analysis(hops2, jump_ms=15))

    def test_correlate_and_verdict(self):
        from app.diagnostics import correlate_spikes, latency_verdict, wan_findings
        # 5 appareils, base 10 ms ; à la minute 100 tous grimpent → généralisé
        series = {i: {100: 80.0, 160: 10.0} for i in range(5)}
        base = {i: 10.0 for i in range(5)}
        corr = correlate_spikes(series, base, factor=3, margin=15, min_devices=4, share=0.5)
        self.assertIn(100, corr["generalized_minutes"])
        self.assertNotIn(160, corr["generalized_minutes"])
        ext = {"1.1.1.1": {"recv": 3, "avg": 120.0, "loss": 0, "jitter": 2}}
        f = wan_findings(ext, gateway_ok=True, ext_warn_ms=80)
        self.assertTrue(any(x["category"] == "wan" for x in f))
        v = latency_verdict(f, corr, ext)
        self.assertIn(v["severity"], ("warning", "critical"))

    def test_bufferbloat_grade(self):
        from app.probes import bloat_grade
        self.assertEqual(bloat_grade(3), "A+")
        self.assertEqual(bloat_grade(45), "B")
        self.assertEqual(bloat_grade(500), "F")
        self.assertIsNone(bloat_grade(None))


class ConflictTest(unittest.TestCase):
    def test_arp_multi_mac(self):
        import struct as _s
        from app import arp
        seen = {}
        # simule parse_reply : deux MAC différentes pour la même IP
        base = arp.build_request(b"\x02\x00\x00\x00\x00\x01", "192.168.1.2", "192.168.1.1")

        def reply(mac_hex):
            r = bytearray(base)
            r[20:22] = _s.pack("!H", 2)
            r[22:28] = bytes.fromhex(mac_hex)
            r[28:32] = socket.inet_aton("192.168.1.1")
            return arp.parse_reply(bytes(r))
        self.assertEqual(reply("aabbccddeeff"), ("192.168.1.1", "aa:bb:cc:dd:ee:ff"))
        self.assertEqual(reply("112233445566"), ("192.168.1.1", "11:22:33:44:55:66"))


class ICMPExtraTest(unittest.TestCase):
    def test_jitter_and_percentile(self):
        st = icmp.stats_from_rtts([10.0, 12.0, 11.0, 20.0], sent=4)
        self.assertEqual(st["recv"], 4)
        self.assertIsNotNone(st["jitter"])
        self.assertEqual(icmp.percentile([1, 2, 3, 4], 50), 2.5)
        self.assertIsNone(icmp.percentile([], 50))

    def test_echo_sized(self):
        pkt = icmp.build_echo(0x1234, 1, 0xABCD, size=100)
        self.assertEqual(icmp.checksum(pkt), 0)
        self.assertEqual(len(pkt) - 8, 100)


BBOX_REPEATERS = [{"list": [
    {"hostindex": 24, "macaddress": "38:17:b1:0d:80:70", "link": "Ethernet",
     "stations": [{"macaddress": "AA:BB:CC:DD:EE:01", "ssid": "Bbox-Maison", "rssi": "-47"}]},
    {"hostindex": 25, "macaddress": "44:15:24:81:c3:38", "link": "Ethernet", "stations": []},
], "stationscount": 2}]

BBOX_HOSTS = [{"hosts": {"list": [
    {"id": 1, "hostname": "salon-tv", "ipaddress": "192.168.1.20", "macaddress": "AA:BB:CC:DD:EE:01",
     "link": "WiFi 5", "active": 1, "lastseen": 0, "devicetype": "TV", "wireless": {"rssi0": -58}},
    {"id": 2, "hostname": "nas", "ipaddress": "192.168.1.30", "macaddress": "AA:BB:CC:DD:EE:02",
     "link": "Ethernet", "active": 0, "lastseen": 3600, "ethernet": {"physicalport": 2}},
    {"id": 3, "hostname": "", "ipaddress": "", "macaddress": "pas-une-mac", "link": "", "active": 0},
]}}]


class FakeBboxProvider:
    """Fournisseur Bouygues sans réseau : l'état se pilote depuis le test."""
    state = {"uptime": 1000, "boots": 2, "internet": 2, "fw": "25.5.76", "logins": 0}

    def __new__(cls, host):
        from app.boxes.bouygues import BouyguesProvider

        class _P(BouyguesProvider):
            def get(self, path):
                return cls._get(self, path)

            def login(self, password):
                return cls._login(self, password)

            def logout(self):
                self.authenticated = False
        return _P(host)

    @staticmethod
    def _get(self, path):
        from app.boxes import BoxAuthError
        st = FakeBboxProvider.state
        if path == "device":
            return [{"device": {"modelname": "F@st5696b", "uptime": st["uptime"], "numberofboots": st["boots"],
                                "running": {"version": st["fw"]}, "using": {"ftth": 1}}}]
        if path == "summary":
            return [{"internet": {"state": st["internet"]}, "wireless": {"radio": 1, "guestenable": 0}}]
        if path == "wan/ip":
            return [{"wan": {"ip": {"address": "89.1.2.3", "gateway": "89.1.0.1", "state": "Up"}}}]
        if path == "wan/ip/stats":
            return [{"wan": {"ip": {"stats": {
                "rx": {"bytes": "1000", "bandwidth": 120, "occupation": 0},
                "tx": {"bytes": "500", "bandwidth": 7400, "occupation": 7}}}}}]
        if path == "hosts":
            if not self.authenticated:
                raise BoxAuthError("authentification requise")
            return BBOX_HOSTS
        if path == "wireless/repeater":
            return BBOX_REPEATERS
        if path == "wireless":
            return BBOX_WIRELESS
        raise AssertionError(path)

    @staticmethod
    def _login(self, password):
        from app.boxes import BoxAuthError
        FakeBboxProvider.state["logins"] += 1
        if password != "bon":
            raise BoxAuthError("mot de passe refusé par la box")
        self.authenticated = True


def bbox_monitor(cfg=None, emit=None):
    """BoxMonitor branché sur la fausse Bbox."""
    from app.box import BoxMonitor
    from app.vault import Vault
    FakeBboxProvider.state.update(uptime=1000, boots=2, internet=2, fw="25.5.76", logins=0)
    cfg, db = cfg or Config(), DB(":memory:")
    cfg.box_enabled = True
    events = []

    async def default_emit(type_, message, device=None, severity="info", data=None, notify=True):
        events.append((type_, severity))

    mon = BoxMonitor(cfg, db, Vault(db, "clé-de-test-longue", "/tmp/nw-unused.key"), emit or default_emit,
                     gateway=lambda: "192.168.1.254")
    mon._factory = lambda pid, host: FakeBboxProvider(host)
    mon.set_provider("bouygues")
    return mon, db, events


class BboxTest(unittest.TestCase):
    def make(self):
        return bbox_monitor()

    def test_host_allowed(self):
        from app.boxes import host_allowed
        for ok in ("192.168.1.254", "10.0.0.1", "mabbox.bytel.fr", "169.254.1.1", "mafreebox.freebox.fr",
                   "livebox"):
            self.assertTrue(host_allowed(ok), ok)
        for bad in ("8.8.8.8", "evil.example.com", "mabbox.bytel.fr.evil.com", "192.168.1.1/x", "", "a@b",
                    "mafreebox.freebox.fr.evil.com"):
            self.assertFalse(host_allowed(bad), bad)

    def test_client_sends_box_host_header(self):
        from app.boxes.bouygues import BouyguesProvider
        seen = {}

        class Resp:
            status = 200

            def read(self):
                return b"[]"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        c = BouyguesProvider("192.168.1.254")
        c.http.opener.open = lambda req, timeout=None: (seen.update(req.header_items()), Resp())[1]
        c.http.request("POST", "/login", form={"password": "x"})
        self.assertEqual(seen.get("Host"), "mabbox.bytel.fr")   # sans lui : 302 puis POST perdu (404)

    def test_parsers(self):
        from app.boxes import bouygues as bbox
        hosts = bbox.parse_hosts(BBOX_HOSTS)
        self.assertEqual(hosts[0]["mac"], "aa:bb:cc:dd:ee:01")
        self.assertTrue(hosts[0]["wifi"])
        self.assertEqual(hosts[0]["rssi"], -58)
        self.assertFalse(hosts[1]["wifi"])
        self.assertEqual(hosts[1]["port"], 2)
        self.assertIsNone(hosts[2]["mac"])
        self.assertEqual(bbox.parse_hosts({"exception": {}}), [])
        st = bbox.parse_wan_stats(FakeBboxProvider("x").get("wan/ip/stats"))
        self.assertEqual((st["rx_bytes"], st["tx_kbps"]), (1000, 7400))  # octets fournis en chaîne

    def test_access_point_assignment(self):
        from app.boxes import bouygues as bbox
        from app.boxes.base import assign_access_points
        hosts = bbox.parse_hosts([{"hosts": {"list": [
            # Wi-Fi listé par le répéteur 24 (la station fait foi)
            {"hostname": "u1", "macaddress": "AA:BB:CC:DD:EE:01", "link": "Wifi 2.4", "active": 1,
             "wireless": {"wexindex": 0, "rssi0": "-29"}},
            # Wi-Fi absent des stations : on retombe sur wexindex (25)
            {"hostname": "tv", "macaddress": "AA:BB:CC:DD:EE:02", "link": "Wifi 5", "active": 1,
             "wireless": {"wexindex": 25, "rssi0": "-79"}},
            # Wi-Fi sans répéteur : la box
            {"hostname": "samsung", "macaddress": "AA:BB:CC:DD:EE:03", "link": "Wifi 5", "active": 1,
             "wireless": {"wexindex": 0}},
            # filaire : toujours la box, même avec un wexindex résiduel
            {"hostname": "br", "macaddress": "AA:BB:CC:DD:EE:04", "link": "Ethernet", "active": 1,
             "wireless": {"wexindex": 24}, "ethernet": {"physicalport": 2}},
            # un répéteur est rattaché à la box, pas à lui-même
            {"hostname": "rep", "macaddress": "44:15:24:81:C3:38", "link": "Wifi 5", "active": 1,
             "wireless": {"wexindex": 25}},
        ]}}])
        reps = bbox.parse_repeaters(BBOX_REPEATERS)
        self.assertEqual([r["label"] for r in reps], ["Répéteur 8070", "Répéteur C338"])
        assign_access_points(hosts, reps, "Bbox")
        self.assertEqual([h["ap"] for h in hosts],
                         ["Répéteur 8070", "Répéteur C338", "Bbox", "Bbox", "Bbox"])
        self.assertEqual(hosts[0]["ssid"], "Bbox-Maison")
        self.assertEqual(hosts[3]["ap_kind"], "box")
        self.assertEqual(bbox.parse_repeaters({"exception": {}}), [])

    def test_poll_public_then_password(self):
        mon, db, _ = self.make()
        snap = asyncio.run(mon.poll())
        self.assertIsNone(snap["hosts"])                    # pas de mot de passe : données publiques seules
        self.assertEqual(snap["device"]["model"], "F@st5696b")
        self.assertEqual(db.q1("SELECT COUNT(*) AS n FROM bbox_samples")["n"], 1)
        mon.set_credentials("bon")
        snap = asyncio.run(mon.poll())
        self.assertEqual(len(snap["hosts"]), 3)
        self.assertEqual(snap["hosts"][0]["ap"], "Répéteur 8070")    # rattachement via /wireless/repeater
        self.assertEqual([r["label"] for r in mon.status()["repeaters"]], ["Répéteur 8070", "Répéteur C338"])
        # le mot de passe est chiffré au repos et absent de la vue publique
        self.assertNotEqual(db.get_meta("box_password"), "bon")
        self.assertNotIn("bon", db.get_meta("box_password"))
        self.assertNotIn("password", mon.status())

    def test_wrong_password_not_retried(self):
        mon, _, events = self.make()
        mon.set_credentials("mauvais")
        for _i in range(3):
            asyncio.run(mon.poll())
        self.assertEqual(FakeBboxProvider.state["logins"], 1)   # un seul essai : pas de verrouillage de la box
        self.assertTrue(mon.auth_failed)
        self.assertEqual(events.count(("bbox_auth", "warning")), 1)
        mon.set_credentials("bon")                               # nouveau mot de passe : on réessaie
        snap = asyncio.run(mon.poll())
        self.assertFalse(mon.auth_failed)
        self.assertEqual(len(snap["hosts"]), 3)

    def test_events(self):
        mon, _, events = self.make()
        asyncio.run(mon.poll())
        self.assertEqual(events, [])                          # premier relevé : rien à comparer
        FakeBboxProvider.state.update(uptime=20, boots=3)
        asyncio.run(mon.poll())
        self.assertIn(("bbox_reboot", "warning"), events)
        FakeBboxProvider.state.update(internet=0)
        asyncio.run(mon.poll())
        self.assertIn(("bbox_internet", "critical"), events)
        FakeBboxProvider.state.update(internet=2, fw="25.6.1")
        asyncio.run(mon.poll())
        self.assertIn(("bbox_internet", "info"), events)
        self.assertIn(("bbox_firmware", "info"), events)

    def test_usage_ignores_counter_reset(self):
        mon, db, _ = self.make()
        for ts, rx, tx in ((1000, 100, 10), (1060, 300, 30), (1120, 5, 1), (1180, 55, 11)):
            db.x("INSERT INTO bbox_samples(ts,rx_bytes,tx_bytes,rx_kbps,tx_kbps) VALUES(?,?,?,?,?)",
                 [ts, rx, tx, 100, 10])
        u = mon.usage(0, 2000, 3600)
        self.assertEqual((u["rx_bytes"], u["tx_bytes"]), (250, 30))   # 200 + 0 (reset) + 50
        self.assertEqual(len(u["series"]), 1)

    def test_api_password_flow(self):
        from starlette.testclient import TestClient

        from app.api import create_app
        from app.engine import Engine
        cfg = Config()
        cfg.demo = True
        cfg.no_auth = True
        cfg.box_host = "192.168.1.254"
        db = DB(os.path.join(tempfile.mkdtemp(), "b.db"))
        eng = Engine(cfg, db)
        eng.box._factory = lambda pid, host: FakeBboxProvider(host)
        FakeBboxProvider.state.update(logins=0)
        with TestClient(create_app(cfg, db, eng)) as c:
            self.assertFalse(c.get("/api/box").json()["has_password"])
            self.assertEqual(c.put("/api/box/provider", json={"provider": "bouygues"}).status_code, 200)
            self.assertEqual(c.put("/api/box/provider", json={"provider": "inconnu"}).status_code, 400)
            self.assertEqual(c.put("/api/box/credentials", json={"password": ""}).status_code, 400)
            r = c.post("/api/box/test", json={"password": "bon"}).json()
            self.assertTrue(r["ok"])
            self.assertEqual(r["hosts"], 3)
            self.assertFalse(c.get("/api/box").json()["has_password"])   # un test n'enregistre rien
            self.assertFalse(c.post("/api/box/test", json={"password": "faux"}).json()["ok"])
            self.assertEqual(c.put("/api/box/credentials", json={"password": "bon"}).status_code, 200)
            s = c.get("/api/box").json()
            self.assertTrue(s["has_password"])
            self.assertNotIn("password", s)
            self.assertFalse(c.delete("/api/box/credentials").json()["has_password"])
            cfg.box_host = "8.8.8.8"
            self.assertEqual(c.put("/api/box/credentials", json={"password": "bon"}).status_code, 400)


# ------------------------------------------------------------------ Zigbee2MQTT
T0 = 1_000_000


def z2m_devices_payload():
    def dev(ieee, name, typ, power="Mains (single phase)", vendor="IKEA", model="E1"):
        return {"ieee_address": ieee, "friendly_name": name, "type": typ, "power_source": power,
                "network_address": 1, "disabled": False, "definition": {"vendor": vendor, "model": model}}
    return json.dumps([
        dev("0x00", "Coordinator", "Coordinator"),
        dev("0x01", "Prise salon", "Router"), dev("0x02", "Prise cuisine", "Router"),
        dev("0x03", "Porte entrée", "EndDevice", "Battery"), dev("0x04", "Salon/température", "EndDevice", "Battery"),
        dev("0x05", "Bureau", "EndDevice", "Battery"), dev("0x06", "Chambre", "EndDevice", "Battery"),
        dev("0x07", "Cave", "EndDevice", "Battery"), dev("0x08", "Garage", "EndDevice", "Battery"),
    ]).encode()


class FakeBroker:
    """Mini broker MQTT : accepte un client, l'abonne et lui rejoue des messages."""

    def __init__(self, messages, connack=0):
        self.messages, self.connack = messages, connack
        self.client_ids, self.subscriptions = [], []

    async def _client(self, reader, writer):
        try:
            await self._serve(reader, writer)
        finally:
            writer.close()          # sinon wait_closed() (Python 3.12) attend indéfiniment

    async def _serve(self, reader, writer):
        from app.mqttsub import read_packet
        from app.notify import mqtt_publish_packet
        head, body = await read_packet(reader)
        (n,) = struct.unpack("!H", body[10:12])
        self.client_ids.append(body[12:12 + n].decode())
        writer.write(bytes([0x20, 0x02, 0x00, self.connack]))
        if self.connack:
            await writer.drain()
            return
        head, body = await read_packet(reader)            # SUBSCRIBE
        (n,) = struct.unpack("!H", body[2:4])
        self.subscriptions.append(body[4:4 + n].decode())
        writer.write(bytes([0x90, 0x03]) + body[:2] + b"\x00")
        for topic, payload in self.messages:
            writer.write(mqtt_publish_packet(topic, payload, True))
        await writer.drain()
        try:
            while True:
                await read_packet(reader)                 # PINGREQ, DISCONNECT…
        except (asyncio.IncompleteReadError, ConnectionError):
            pass

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()


def z2m_monitor(cfg=None):
    from app.vault import Vault
    from app.z2m import Z2MMonitor
    cfg, db = cfg or Config(), DB(":memory:")
    events = []

    async def emit(type_, message, device=None, severity="info", data=None, notify=True):
        events.append((type_, severity))

    return Z2MMonitor(cfg, db, Vault(db, "clé-de-test-longue", "/tmp/nw-unused.key"), emit), db, events


class MqttClientTest(unittest.TestCase):
    def test_packets(self):
        from app.mqttsub import parse_publish, subscribe_packet
        from app.notify import mqtt_publish_packet
        self.assertEqual(subscribe_packet(1, ["a/#"]), b"\x82\x08\x00\x01\x00\x03a/#\x00")
        pkt = mqtt_publish_packet("z/x", b"hello", True)
        self.assertEqual(parse_publish(pkt[0] & 0x0F, pkt[2:]), ("z/x", b"hello", None))
        body = b"\x00\x01t\x00\x07ok"                       # QoS 1 : identifiant de paquet avant la charge
        self.assertEqual(parse_publish(0x02, body), ("t", b"ok", 7))

    def test_subscriber_delivers(self):
        from app.mqttsub import MQTTSubscriber

        async def go():
            async with FakeBroker([("zigbee2mqtt/bridge/state", b"online")]) as b:
                cfg = Config()
                cfg.mqtt_host, cfg.mqtt_port = "127.0.0.1", b.port
                got = []
                sub = MQTTSubscriber(cfg, ["zigbee2mqtt/#"], lambda t, p: got.append((t, p)))
                task = asyncio.create_task(sub.run())
                for _ in range(50):
                    if got:
                        break
                    await asyncio.sleep(0.05)
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                return got, b
        got, b = asyncio.run(go())
        self.assertEqual(got, [("zigbee2mqtt/bridge/state", b"online")])
        self.assertEqual(b.subscriptions, ["zigbee2mqtt/#"])
        self.assertEqual(b.client_ids, ["netwatch-z2m"])   # distinct du publieur « netwatch » (sinon le broker le déconnecte)

    def test_error_wording(self):
        from app.mqttsub import _why
        self.assertEqual(_why(asyncio.TimeoutError()), "délai dépassé")        # str() vide : pas de « () »
        self.assertEqual(_why(OSError("Connection refused")), "Connection refused")
        self.assertEqual(_why(asyncio.IncompleteReadError(b"", 1)), "connexion fermée par le broker")

    def test_probe_errors(self):
        from app.mqttsub import MQTTError, probe

        async def refused():
            async with FakeBroker([], connack=4) as b:
                cfg = Config()
                cfg.mqtt_host, cfg.mqtt_port = "127.0.0.1", b.port
                await probe(cfg, ["x/#"], wait=0.2)
        with self.assertRaisesRegex(MQTTError, "refusé"):
            asyncio.run(refused())
        cfg = Config()
        cfg.mqtt_host, cfg.mqtt_port = "127.0.0.1", 1                 # rien n'écoute
        with self.assertRaisesRegex(MQTTError, "injoignable"):
            asyncio.run(probe(cfg, ["x/#"], wait=0.2))


class Z2MIngestTest(unittest.TestCase):
    def feed(self, mon, *msgs):
        async def go():
            for topic, payload in msgs:
                await mon.handle("zigbee2mqtt/" + topic, payload if isinstance(payload, bytes) else payload.encode())
        asyncio.run(go())

    def test_parsers(self):
        from app import z2m
        self.assertTrue(z2m.parse_state(b"online"))
        self.assertFalse(z2m.parse_state(b'{"state":"offline"}'))
        self.assertIsNone(z2m.parse_state(b"n'importe quoi"))
        self.assertEqual(z2m.log_category("Failed to ping 'x' (attempt 1/1, ZCL command failed (Delivery failed))"), "delivery")
        self.assertEqual(z2m.log_category("Interview failed for 'y'"), "interview")
        self.assertEqual(z2m.log_category("autre chose"), "other")
        info = z2m.parse_info(json.dumps({"version": "2.1.0", "network": {"channel": 11, "pan_id": 1},
                                          "coordinator": {"type": "zStack3x0", "meta": {"revision": 20230507}},
                                          "config": {"availability": {"enabled": False}}}).encode())
        self.assertEqual((info["channel"], info["coordinator_fw"], info["availability_enabled"]), (11, 20230507, False))
        nm = z2m.parse_networkmap(json.dumps({"status": "ok", "data": {"value": {
            "nodes": [{"ieeeAddr": "0x01", "friendlyName": "A", "type": "Router", "networkAddress": 1}],
            "links": [{"sourceIeeeAddr": "0x01", "targetIeeeAddr": "0x03", "lqi": 90, "relationship": 1, "depth": 1}]}}}).encode())
        self.assertEqual(nm["links"][0], {"src": "0x01", "dst": "0x03", "lqi": 90, "depth": 1, "rel": 1})
        self.assertIsNone(z2m.parse_networkmap(b'{"status":"error"}'))

    def test_availability_transitions_and_buffering(self):
        mon, db, events = z2m_monitor()
        # la disponibilité arrive avant la liste des appareils : elle est mise en attente puis rejouée
        self.feed(mon, ("Porte entrée/availability", '{"state":"online"}'))
        self.assertEqual(db.q("SELECT * FROM z2m_avail"), [])
        self.feed(mon, ("bridge/devices", z2m_devices_payload()))
        rows = db.q("SELECT ieee, online, src FROM z2m_avail")
        self.assertEqual(rows, [{"ieee": "0x03", "online": 1, "src": "init"}])     # état initial, pas une déconnexion
        self.assertEqual(len(mon.names), 8)                                        # coordinateur exclu
        self.feed(mon, ("Porte entrée/availability", "online"))                    # inchangé : rien de nouveau
        self.assertEqual(len(db.q("SELECT * FROM z2m_avail")), 1)
        self.feed(mon, ("Porte entrée/availability", "offline"), ("Porte entrée/availability", "online"),
                  ("Salon/température/availability", "online"))                    # nom contenant « / »
        self.assertEqual([(r["ieee"], r["online"]) for r in db.q("SELECT * FROM z2m_avail ORDER BY rowid")],
                         [("0x03", 1), ("0x03", 0), ("0x03", 1), ("0x04", 1)])
        self.assertEqual(db.q1("SELECT online FROM z2m_devices WHERE ieee='0x03'")["online"], 1)

    def test_bridge_state_events(self):
        mon, db, events = z2m_monitor()
        self.feed(mon, ("bridge/state", '{"state":"online"}'))
        self.assertEqual(events, [])                                              # premier état : pas d'alerte
        self.feed(mon, ("bridge/state", "offline"), ("bridge/state", "offline"), ("bridge/state", "online"))
        self.assertEqual(events, [("z2m_bridge", "critical"), ("z2m_bridge", "info")])
        self.assertEqual([r["online"] for r in db.q("SELECT online FROM z2m_avail WHERE ieee='bridge' ORDER BY rowid")],
                         [1, 0, 1])

    def test_samples_logs_events(self):
        mon, db, _ = z2m_monitor()
        self.feed(mon, ("bridge/devices", z2m_devices_payload()),
                  ("Porte entrée", '{"linkquality": 88, "battery": 12}'),
                  ("Porte entrée", '{"linkquality": 10}'),                      # dans les 5 min : ignoré
                  ("bridge/logging", json.dumps({"level": "error", "message":
                   "Failed to ping 'Porte entrée' (attempt 1/1, Delivery failed)"})),
                  ("bridge/logging", json.dumps({"level": "info", "message": "bruit"})),
                  ("bridge/event", json.dumps({"type": "device_announce", "data": {"friendly_name": "Cave", "ieee_address": "0x07"}})),
                  ("bridge/event", json.dumps({"type": "autre", "data": {}})))
        self.assertEqual(db.q("SELECT ieee, lqi, battery FROM z2m_samples"), [{"ieee": "0x03", "lqi": 88, "battery": 12}])
        self.assertEqual(db.q1("SELECT lqi, battery FROM z2m_devices WHERE ieee='0x03'"), {"lqi": 88, "battery": 12})
        logs = db.q("SELECT kind, level, ieee, cat FROM z2m_log ORDER BY id")
        self.assertEqual(logs, [{"kind": "log", "level": "error", "ieee": "0x03", "cat": "delivery"},
                                {"kind": "device_announce", "level": "info", "ieee": "0x07", "cat": "other"}])

    def test_other_base_topic_ignored(self):
        mon, db, _ = z2m_monitor()
        asyncio.run(mon.handle("autre/bridge/devices", z2m_devices_payload()))
        self.assertEqual(db.q("SELECT * FROM z2m_devices"), [])

    def test_monitor_end_to_end(self):
        async def go():
            msgs = [("zigbee2mqtt/bridge/devices", z2m_devices_payload()),
                    ("zigbee2mqtt/Cave/availability", b'{"state":"offline"}')]
            async with FakeBroker(msgs) as b:
                cfg = Config()
                cfg.mqtt_host, cfg.mqtt_port, cfg.z2m_enabled = "127.0.0.1", b.port, True
                mon, db, _ = z2m_monitor(cfg)
                task = asyncio.create_task(mon.run())
                for _ in range(80):
                    if db.q("SELECT * FROM z2m_avail"):
                        break
                    await asyncio.sleep(0.05)
                st = mon.status()
                cfg.z2m_enabled = False                   # désactivation à chaud : l'écoute s'arrête
                await asyncio.sleep(3.2)
                off = mon.status()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                return db, st, off
        db, st, off = asyncio.run(go())
        self.assertEqual(db.q("SELECT ieee, online FROM z2m_avail"), [{"ieee": "0x07", "online": 0}])
        self.assertTrue(st["connected"])
        self.assertEqual((st["devices"], st["offline"]), (8, 1))
        self.assertFalse(off["connected"])

    def test_test_logic(self):
        async def go(with_bridge):
            msgs = [("zigbee2mqtt/bridge/state", b'{"state":"online"}'),
                    ("zigbee2mqtt/bridge/devices", z2m_devices_payload())] if with_bridge else []
            async with FakeBroker(msgs) as b:
                cfg = Config()
                cfg.mqtt_host, cfg.mqtt_port = "127.0.0.1", b.port
                mon, _, _ = z2m_monitor(cfg)
                return await mon.test()
        ok = asyncio.run(go(True))
        self.assertEqual((ok["ok"], ok["bridge"], ok["devices"]), (True, "online", 8))
        silent = asyncio.run(go(False))
        self.assertTrue(silent["ok"])
        self.assertIn("base_topic", silent["warning"])
        mon, _, _ = z2m_monitor()
        self.assertFalse(asyncio.run(mon.test())["ok"])                           # aucun broker configuré

    def test_secrets_encrypted_and_reloaded(self):
        mon, db, _ = z2m_monitor()
        mon.set_mqtt_password("s3cret-mqtt")
        mon.set_ha_token("token-ha-tres-long")
        for key in ("mqtt_password", "ha_token"):
            self.assertNotIn("s3cret", db.get_meta(key))
            self.assertNotIn("token-ha", db.get_meta(key))
        self.assertEqual(mon.cfg.mqtt_password, "s3cret-mqtt")
        blob = json.dumps(mon.status())
        self.assertNotIn("s3cret", blob)
        self.assertNotIn("token-ha", blob)
        self.assertTrue(mon.status()["has_password"] and mon.status()["ha"]["has_token"])
        cfg2 = Config()                                                           # redémarrage : relu depuis le coffre
        from app.vault import Vault
        from app.z2m import Z2MMonitor
        Z2MMonitor(cfg2, db, Vault(db, "clé-de-test-longue", "/tmp/nw-unused.key"), None)
        self.assertEqual(cfg2.mqtt_password, "s3cret-mqtt")
        with self.assertRaises(ValueError):
            mon.set_mqtt_password("")


class Z2MReportTest(unittest.TestCase):
    END = T0 + 86400

    def build(self, bridge=()):
        """Réseau de 8 appareils ; 24 h de données construites à la main."""
        mon, db, _ = z2m_monitor()
        asyncio.run(mon.handle("zigbee2mqtt/bridge/devices", z2m_devices_payload()))
        ieees = [f"0x0{i}" for i in range(1, 9)]
        for i in ieees:
            db.x("INSERT INTO z2m_avail(ts, ieee, online, src) VALUES(?,?,1,'init')", [T0, i])

        def drop(ieee, ts, back=90):
            db.x("INSERT INTO z2m_avail(ts, ieee, online) VALUES(?,?,0)", [ts, ieee])
            db.x("INSERT INTO z2m_avail(ts, ieee, online) VALUES(?,?,1)", [ts + back, ieee])
        for k in range(5):                                      # « Porte entrée » : 5 déconnexions isolées
            drop("0x03", T0 + 5000 + k * 9000, 60)
        for n, i in enumerate(ieees):                           # coupure globale à T0+40000
            drop(i, T0 + 40000 + n * 4, 120)
        for n, i in enumerate(("0x02", "0x05", "0x06")):        # coupure de groupe à T0+60000
            drop(i, T0 + 60000 + n * 10, 300)
        for s, e in bridge:
            db.x("INSERT INTO z2m_avail(ts, ieee, online) VALUES(?,?,0)", [s, "bridge"])
            db.x("INSERT INTO z2m_avail(ts, ieee, online) VALUES(?,?,1)", [e, "bridge"])
        for t, lqi in ((T0 + 100, 30), (T0 + 500, 40)):
            db.x("INSERT INTO z2m_samples(ts, ieee, lqi, battery) VALUES(?,?,?,?)", [t, "0x03", lqi, 9])
        db.x("UPDATE z2m_devices SET battery=9, lqi=40 WHERE ieee='0x03'")
        return mon, db

    def report(self, mon, info=None, netmap=None):
        from app import z2mdiag
        return z2mdiag.build_report(mon.db, T0, self.END, info, netmap)

    def test_full_scenario(self):
        mon, _ = self.build(bridge=[(T0 + 20000, T0 + 20300)])
        r = self.report(mon, info={"channel": 11})
        keys = {f["key"] for f in r["findings"]}
        self.assertTrue({"bridge_down", "global_outage", "group_drops", "flap:0x03", "weak_links", "low_battery",
                         "channel"} <= keys, keys)
        self.assertEqual(r["verdict"]["severity"], "critical")
        self.assertEqual(r["findings"][0]["severity"], "critical")              # trié du plus grave au moins grave
        self.assertEqual(r["summary"]["devices"], 8)
        self.assertEqual(r["summary"]["bridge_outages"], 1)
        self.assertTrue(r["coverage"]["complete"])
        causes = sorted(c["cause"] for c in r["clusters"])
        self.assertEqual(causes, ["global", "group"])
        glob = next(c for c in r["clusters"] if c["cause"] == "global")
        self.assertEqual((glob["n"], glob["back_after_s"]), (8, 120))
        porte = next(d for d in r["devices"] if d["name"] == "Porte entrée")
        self.assertEqual(porte["drops"], 6)                                      # 5 isolées + la coupure globale
        self.assertEqual(r["devices"][0]["ieee"], "0x03")                        # le plus instable en tête
        self.assertEqual(porte["offline_s"], 5 * 60 + 120)
        self.assertEqual(len(porte["strip"]), 96)
        self.assertEqual(porte["lqi_avg"], 35)
        self.assertEqual(max(p["offline"] for p in r["timeline"]), 8)

    def test_drops_during_bridge_outage_not_blamed_on_devices(self):
        mon, _ = self.build(bridge=[(T0 + 39990, T0 + 40200)])                  # le pont tombe pendant la coupure globale
        r = self.report(mon)
        porte = next(d for d in r["devices"] if d["name"] == "Porte entrée")
        self.assertEqual(porte["drops"], 5)
        self.assertNotIn("global_outage", {f["key"] for f in r["findings"]})
        self.assertIn("bridge_down", {f["key"] for f in r["findings"]})

    def test_quiet_network_and_no_data(self):
        mon, db, _ = z2m_monitor()
        asyncio.run(mon.handle("zigbee2mqtt/bridge/devices", z2m_devices_payload()))
        from app import z2mdiag
        r = z2mdiag.build_report(db, T0, T0 + 86400, {"channel": 25, "availability_enabled": False})
        self.assertEqual(r["verdict"]["severity"], "info")
        self.assertIn("no_availability", {f["key"] for f in r["findings"]})
        for d in (f"0x0{i}" for i in range(1, 9)):
            db.x("INSERT INTO z2m_avail(ts, ieee, online, src) VALUES(?,?,1,'init')", [T0, d])
        r = z2mdiag.build_report(db, T0, T0 + 86400, {"channel": 25})
        self.assertEqual((r["verdict"]["severity"], r["summary"]["drops"]), ("good", 0))
        self.assertEqual(r["summary"]["availability_pct"], 100.0)
        self.assertEqual(r["findings"], [])

    def test_partial_coverage(self):
        mon, db, _ = z2m_monitor()
        asyncio.run(mon.handle("zigbee2mqtt/bridge/devices", z2m_devices_payload()))
        db.x("INSERT INTO z2m_avail(ts, ieee, online, src) VALUES(?,?,1,'init')", [T0 + 43200, "0x03"])
        from app import z2mdiag
        r = z2mdiag.build_report(db, T0, T0 + 86400)
        self.assertFalse(r["coverage"]["complete"])
        self.assertEqual(r["coverage"]["hours"], 12.0)
        dev = next(d for d in r["devices"] if d["ieee"] == "0x03")
        self.assertEqual(dev["covered_s"], 43200)
        self.assertEqual(dev["strip"][:48], [None] * 48)                        # rien avant le début des données

    def test_netmap_parent_and_channel_overlap(self):
        from app import z2mdiag
        mon, _ = self.build()
        netmap = {"ts": 5, "nodes": [{"ieee": "0x02", "name": "Prise cuisine", "type": "Router", "nwk": 2}],
                  "links": [{"src": "0x02", "dst": d, "lqi": 120, "rel": 1, "depth": 1} for d in ("0x05", "0x06")]}
        r = self.report(mon, netmap=netmap)
        self.assertEqual(next(d for d in r["devices"] if d["ieee"] == "0x05")["parent"], "Prise cuisine")
        grp = next(c for c in r["clusters"] if c["cause"] == "group")
        self.assertEqual(grp["shared_parent"], "Prise cuisine")
        self.assertIsNone(z2mdiag._channel_overlap(15))
        self.assertIsNone(z2mdiag._channel_overlap(25))
        self.assertEqual(z2mdiag._channel_overlap(11), "1")
        self.assertEqual(z2mdiag._channel_overlap(22), "11")
        self.assertEqual(z2mdiag._channel_overlap(17), "6")

    def test_segments_and_clusters(self):
        from app import z2mdiag
        rows = [{"ts": 100, "online": 0}, {"ts": 150, "online": 1}, {"ts": 160, "online": 1}]
        segs, drops = z2mdiag.segments({"online": 1}, rows, 0, 200)
        self.assertEqual(segs, [(0, 100, True), (100, 150, False), (150, 200, True)])
        self.assertEqual(drops, [100])
        self.assertEqual(z2mdiag.segments(None, [], 0, 10), ([], []))
        ev = [(0, "a"), (30, "b"), (60, "c"), (1000, "d"), (1010, "e")]
        self.assertEqual([len(g) for g in z2mdiag.find_clusters(ev, 10)], [3])  # 2 appareils ne suffisent pas sur un gros réseau
        self.assertEqual([len(g) for g in z2mdiag.find_clusters(ev, 3)], [3, 2])


HA_STATES = [
    {"entity_id": "light.prise_salon", "state": "on"},
    {"entity_id": "sensor.prise_salon_power", "state": "3"},
    {"entity_id": "sensor.0x0000000000000003_linkquality", "state": "60"},          # nommage par adresse IEEE
    {"entity_id": "binary_sensor.porte_entree_contact", "state": "off"},
    {"entity_id": "sensor.porte_entree_battery", "state": "80"},
    {"entity_id": "sensor.salon_temperature_humidity", "state": "40"},            # nom contenant « / » → slug
    {"entity_id": "sensor.phone_battery_level", "state": "50"},                     # autre intégration : ignoré
    {"entity_id": "update.prise_salon", "state": "off"},                            # domaine ignoré
]


class HAImportTest(unittest.TestCase):
    def test_url_allowed(self):
        from app.hahistory import url_allowed
        for ok in ("http://192.168.1.11:8123", "https://homeassistant.local:8123", "http://homeassistant:8123",
                   "http://127.0.0.1:8123", "http://ha.lan"):
            self.assertTrue(url_allowed(ok), ok)
        for bad in ("http://8.8.8.8:8123", "https://evil.example.com", "http://192.168.1.11@evil.com",
                    "ftp://192.168.1.11", "", "javascript:alert(1)", "http://homeassistant.local.evil.com"):
            self.assertFalse(url_allowed(bad), bad)

    def test_matching(self):
        from app.hahistory import match_entities, pick_entities, slug
        self.assertEqual(slug("Salon/température"), "salon_temperature")
        self.assertEqual(slug("(i)Bureau"), "i_bureau")
        devs = [{"ieee": "0x0000000000000001", "name": "Prise salon", "type": "Router"},
                {"ieee": "0x0000000000000003", "name": "Sans rapport", "type": "EndDevice"},
                {"ieee": "0x0000000000000004", "name": "Salon/température", "type": "EndDevice"},
                {"ieee": "0x0000000000000005", "name": "Porte entrée", "type": "EndDevice"},
                {"ieee": "0x0000000000000000", "name": "Coordinator", "type": "Coordinator"}]
        m = match_entities(devs, HA_STATES)
        self.assertEqual(sorted(m["0x0000000000000001"]), ["light.prise_salon", "sensor.prise_salon_power"])
        self.assertEqual(m["0x0000000000000003"], ["sensor.0x0000000000000003_linkquality"])
        self.assertEqual(m["0x0000000000000004"], ["sensor.salon_temperature_humidity"])
        self.assertNotIn("0x0000000000000000", m)
        self.assertEqual(pick_entities(["sensor.x_battery", "sensor.x", "light.x"]), ["light.x", "sensor.x"])
        self.assertEqual(pick_entities(["sensor.x_battery"]), ["sensor.x_battery"])   # métrique seule : dernier recours

    def test_device_info_and_fallback(self):
        from app import hahistory
        real_tpl = hahistory._template
        try:
            hahistory._template = lambda *a, **k: "\n  " + json.dumps({
                "ent": {"sensor.a": "d1", "sensor.b": "d2"},
                "dev": {"d1": {"n": "Cuisine", "i": ["mqtt zigbee2mqtt_0x00158D0005D246CF"]},   # majuscules : normalisées
                        "d2": {"n": "Bridge", "i": ["mqtt zigbee2mqtt_bridge_0x00"]}}}) + "\n"
            info = hahistory.device_info("http://ha", "tok")
            self.assertEqual(info["names"], {"0x00158d0005d246cf": "Cuisine"})
            self.assertEqual(info["entities"], {"sensor.a": "0x00158d0005d246cf"})
            hahistory._template = lambda *a, **k: "pas du json"
            with self.assertRaises(hahistory.HAError):
                hahistory.device_info("http://ha", "tok")
            # le modèle échoue : l'import continue avec l'association par nom et signale l'absence de noms
            mon, db, _ = z2m_monitor()
            asyncio.run(mon.handle("zigbee2mqtt/bridge/devices", z2m_devices_payload()))
            db.x("UPDATE z2m_devices SET ieee='0x0000000000000001' WHERE ieee='0x01'")
            real_get = hahistory._get
            hahistory._get = lambda base, token, path, timeout=60.0, verify=True: (
                [{"entity_id": "light.prise_salon", "state": "on"}] if path == "states" else [])
            try:
                res = hahistory.import_history(db, "http://192.168.1.11:8123", "tok", 24)
            finally:
                hahistory._get = real_get
            self.assertEqual((res["matched"], res["named"]), (1, 0))
            self.assertIn("Noms Home Assistant non récupérés", res["warning"])
        finally:
            hahistory._template = real_tpl

    def test_name_guessing(self):
        from app import z2mnames as zn
        ent = lambda i, c=None, n=None, a=(): {"id": i, "class": c, "name": n or i, "automations": list(a)}
        devs = [{"ieee": "0x0000000000000001", "name": "0x0000000000000001", "ha_name": None, "vendor": None, "model": None},
                {"ieee": "0x0000000000000002", "name": "0x0000000000000002", "ha_name": "Porte du salon", "vendor": None, "model": None},
                {"ieee": "0x0000000000000003", "name": "0x0000000000000003", "ha_name": None, "vendor": None, "model": None},
                {"ieee": "0x0000000000000004", "name": "0x0000000000000004", "ha_name": None, "vendor": None, "model": None},
                {"ieee": "0x0000000000000005", "name": "0x0000000000000005", "ha_name": None, "vendor": "Aqara", "model": "X1"},
                {"ieee": "0x0000000000000006", "name": "0x0000000000000006", "ha_name": None, "vendor": None, "model": None},
                {"ieee": "0x0000000000000007", "name": "Déjà nommé", "ha_name": None, "vendor": None, "model": None},
                {"ieee": "0x0000000000000008", "name": "0x0000000000000008", "ha_name": "Cuisine", "vendor": None, "model": None}]
        ctx = {
            "0x0000000000000001": {"area": "Salon", "ents": [ent("sensor.x_battery", "battery"), ent("binary_sensor.x_contact", "door")]},
            "0x0000000000000002": {"area": "Salon", "ents": [ent("binary_sensor.y_contact", "door")]},      # même pièce, même type
            "0x0000000000000003": {"area": "Salon", "ents": [ent("binary_sensor.z_contact", "door")]},
            "0x0000000000000004": {"area": None, "ents": [ent("binary_sensor.m", "motion", "Couloir mouvement", ["Lumière couloir"])]},
            "0x0000000000000005": {"area": "Garage", "ents": [ent("sensor.q_battery", "battery")]},          # pièce + modèle seulement
            "0x0000000000000006": {"area": None, "ents": []},                                                # rien à en tirer
        }
        g = zn.guess(devs, ctx)
        self.assertEqual(g["0x0000000000000001"]["name"], "Salon – ouverture")
        self.assertEqual(g["0x0000000000000001"]["confidence"], "haute")
        self.assertEqual(g["0x0000000000000003"]["name"], "Salon – ouverture 2")                          # doublon numéroté
        self.assertEqual(g["0x0000000000000004"]["name"], "Mouvement – Lumière couloir")                  # sans pièce : automatisation
        self.assertEqual(g["0x0000000000000004"]["confidence"], "moyenne")
        self.assertEqual(g["0x0000000000000005"]["name"], "Garage – Aqara X1")
        for k in ("0x0000000000000002", "0x0000000000000006", "0x0000000000000007", "0x0000000000000008"):
            self.assertNotIn(k, g)        # nommé dans HA, nom lisible, ou aucun indice : pas de suggestion inventée
        # priorité des types : ouverture/mouvement > lumière > mesures > télécommande ; bruit ignoré
        self.assertEqual(zn._kind([ent("light.l"), ent("sensor.l_temperature", "temperature"), ent("sensor.l_linkquality")]), "lumière")
        self.assertEqual(zn._kind([ent("sensor.t", "temperature"), ent("sensor.h", "humidity")]), "température/humidité")
        self.assertEqual(zn._kind([ent("sensor.b_action"), ent("sensor.b_battery", "battery")]), "télécommande")
        self.assertIsNone(zn._kind([ent("sensor.b_battery", "battery"), ent("update.b")]))

    def test_tls_verification(self):
        import ssl

        from app.hahistory import _context
        self.assertIsNone(_context(True))                                              # défaut : vérification normale
        ctx = _context(False)
        self.assertEqual((ctx.verify_mode, ctx.check_hostname), (ssl.CERT_NONE, False))
        self.assertTrue(Config().ha_verify_tls)

    def test_timeline_needs_every_entity_unavailable(self):
        from app.hahistory import availability_timeline as tl
        h = {"a": [(0, "on"), (100, "unavailable"), (300, "on")],
             "b": [(0, "5"), (110, "unavailable"), (250, "4")]}
        # hors ligne seulement quand les deux le sont : de 110 à 250
        self.assertEqual(tl(h), [(0, True), (110, False), (250, True)])
        self.assertEqual(tl({}), [])

    def test_import_history(self):
        import datetime

        from app import hahistory
        mon, db, _ = z2m_monitor()
        asyncio.run(mon.handle("zigbee2mqtt/bridge/devices", z2m_devices_payload()))
        # les appareils de la liste Z2M de test portent des adresses courtes (0x01…) : on les aligne sur les entités HA
        db.x("UPDATE z2m_devices SET ieee='0x0000000000000001' WHERE ieee='0x01'")
        db.x("UPDATE z2m_devices SET ieee='0x0000000000000005' WHERE ieee='0x05'")
        db.x("UPDATE z2m_devices SET name='Porte entrée', ieee='0x0000000000000003' WHERE ieee='0x03'")
        db.x("UPDATE z2m_devices SET name='0x0000000000000006', ieee='0x0000000000000006' WHERE ieee='0x06'")
        now = time.time()

        def iso(t):
            return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat()
        start = now - 24 * 3600
        calls, verifs = [], []

        def fake_get(base, token, path, timeout=60.0, verify=True):
            calls.append(path)
            verifs.append(verify)
            self.assertEqual(token, "tok")
            if path == "states":
                return HA_STATES + [{"entity_id": "sensor.ancien_nom_temp", "state": "20"}]
            return [
                [{"entity_id": "light.prise_salon", "state": "on", "last_changed": iso(start - 999)},
                 {"state": "unavailable", "last_changed": iso(now - 7200)},
                 {"state": "on", "last_changed": iso(now - 7000)}],
                [{"entity_id": "sensor.prise_salon_power", "state": "3", "last_changed": iso(start - 5)},
                 {"state": "unavailable", "last_changed": iso(now - 7200)},
                 {"state": "3", "last_changed": iso(now - 7000)}],
                [{"entity_id": "sensor.0x0000000000000003_linkquality", "state": "61", "last_changed": iso(start)}],
                [{"entity_id": "binary_sensor.porte_entree_contact", "state": "off", "last_changed": iso(start)}],
                [{"entity_id": "sensor.porte_entree_battery", "state": "77", "last_changed": iso(start)}],
            ]
        real, real_tpl = hahistory._get, hahistory._template
        hahistory._get = fake_get
        hahistory._template = lambda *a, **k: json.dumps({
            "ent": {"light.prise_salon": "dev1", "sensor.ancien_nom_temp": "dev5", "sensor.autre": "devX",
                    "binary_sensor.capteur_6": "dev6", "sensor.capteur_6_battery": "dev6"},
            "dev": {"dev1": {"n": "Prise du salon", "i": ["mqtt zigbee2mqtt_0x0000000000000001"]},
                    "dev5": {"n": "Bureau", "i": ["mqtt zigbee2mqtt_0x0000000000000005"]},
                    "dev6": {"n": "0x0000000000000006", "i": ["mqtt zigbee2mqtt_0x0000000000000006"], "a": "Chambre",
                             "m": "MCCGQ11LM", "v": "Aqara"},
                    "devX": {"n": "Autre", "i": ["mqtt un_autre_identifiant"]}},
            "ex": {"binary_sensor.capteur_6": {"c": "door", "f": "Capteur 6 Ouverture", "a": ["Fermer volets chambre"]},
                   "sensor.capteur_6_battery": {"c": "battery", "f": "Capteur 6 Batterie", "a": []}}})
        try:
            res = hahistory.import_history(db, "http://192.168.1.11:8123", "tok", 24, verify_tls=False)
            self.assertEqual(set(verifs), {False})                                       # l'option atteint chaque requête
            with self.assertRaises(hahistory.HAError):
                hahistory.import_history(db, "https://evil.example.com", "tok", 24)
            # « Salon/température » associé par son nom, « Bureau » par le registre HA (entité renommée), sans historique
            self.assertEqual((res["matched"], res["with_history"], res["drops"]), (4, 2, 1))
            self.assertNotIn("Bureau", res["unmatched"])
            # le nom « 0x…06 » de HA n'est qu'une adresse : pas compté comme nom, mais une suggestion est déduite
            self.assertEqual((res["named"], res["guessed"], res["warning"]), (2, 1, None))
            g = json.loads(db.q1("SELECT ha_guess FROM z2m_devices WHERE ieee='0x0000000000000006'")["ha_guess"])
            self.assertEqual((g["name"], g["confidence"]), ("Chambre – ouverture", "haute"))
            self.assertIn("automatisations : Fermer volets chambre", g["evidence"])
            self.assertIsNone(db.q1("SELECT ha_name FROM z2m_devices WHERE ieee='0x0000000000000006'")["ha_name"])
            self.assertEqual(db.q1("SELECT ha_name FROM z2m_devices WHERE ieee='0x0000000000000001'")["ha_name"], "Prise du salon")
            rows = db.q("SELECT online, src FROM z2m_avail WHERE ieee='0x0000000000000001' ORDER BY ts")
            self.assertEqual([(r["online"], r["src"]) for r in rows], [(1, "ha"), (0, "ha"), (1, "ha")])
            self.assertIn("filter_entity_id=", calls[1])
            self.assertIn("%2B00:00", calls[1])                                          # « + » de l'horodatage encodé
            self.assertEqual(db.q1("SELECT lqi, battery FROM z2m_samples WHERE ieee='0x0000000000000003'"),
                             {"lqi": 61, "battery": 77})
            # une seconde importation remplace la première au lieu de la doubler
            hahistory.import_history(db, "http://192.168.1.11:8123", "tok", 24)
        finally:
            hahistory._get, hahistory._template = real, real_tpl
        self.assertEqual(db.q1("SELECT COUNT(*) AS n FROM z2m_avail WHERE ieee='0x0000000000000001'")["n"], 3)
        # et le diagnostic l'exploite comme les données MQTT
        from app import z2mdiag
        r = z2mdiag.build_report(db, int(start), int(now))
        dev = next(d for d in r["devices"] if d["ieee"] == "0x0000000000000001")
        self.assertEqual((dev["drops"], dev["offline_s"]), (1, 200))
        self.assertEqual((dev["name"], dev["z2m_name"]), ("Prise du salon", "Prise salon"))   # nom HA en principal
        self.assertIsNone(next(d for d in r["devices"] if d["ieee"] == "0x0000000000000005")["z2m_name"])  # identique : pas de doublon
        unnamed = next(d for d in r["devices"] if d["ieee"] == "0x0000000000000006")
        self.assertEqual((unnamed["name"], unnamed["z2m_name"]), ("≈ Chambre – ouverture", "0x0000000000000006"))
        self.assertEqual(unnamed["guess"]["confidence"], "haute")            # suggestion signalée, jamais un vrai nom


class Z2MApiTest(unittest.TestCase):
    def test_api(self):
        from starlette.testclient import TestClient

        from app.api import create_app
        from app.engine import Engine
        cfg = Config()
        cfg.demo = True
        cfg.no_auth = True
        db = DB(os.path.join(tempfile.mkdtemp(), "z.db"))
        eng = Engine(cfg, db)
        with TestClient(create_app(cfg, db, eng)) as c:
            s = c.get("/api/z2m").json()
            self.assertFalse(s["enabled"] or s["mqtt_configured"])
            r = c.patch("/api/settings", json={"mqtt_host": "127.0.0.1", "mqtt_port": "1884", "z2m_topic": "z2m",
                                              "ha_url": "http://192.168.1.11:8123"}).json()
            self.assertEqual(r["errors"], {})
            s = c.get("/api/z2m").json()
            self.assertEqual((s["host"], s["port"], s["topic"]), ("127.0.0.1", 1884, "z2m"))
            self.assertEqual(c.put("/api/z2m/mqtt-password", json={"password": ""}).status_code, 400)
            s = c.put("/api/z2m/mqtt-password", json={"password": "pw-mqtt"}).json()
            self.assertTrue(s["has_password"])
            self.assertNotIn("pw-mqtt", json.dumps(s))
            self.assertTrue(c.put("/api/z2m/ha-token", json={"token": "abc"}).json()["ha"]["has_token"])
            self.assertFalse(c.delete("/api/z2m/ha-token").json()["ha"]["has_token"])
            self.assertFalse(c.delete("/api/z2m/mqtt-password").json()["has_password"])
            cfg.ha_url = "https://evil.example.com"
            self.assertEqual(c.put("/api/z2m/ha-token", json={"token": "abc"}).status_code, 400)
            rep = c.get("/api/z2m/report?hours=24").json()
            self.assertEqual(rep["summary"]["devices"], 0)
            self.assertEqual(c.get("/api/z2m/report?hours=zzz").json()["window_hours"], 24.0)
            self.assertFalse(c.post("/api/z2m/import", json={}).json()["ok"])               # pas de jeton
            self.assertFalse(c.post("/api/z2m/networkmap").json()["ok"])                    # pas connecté


BBOX_WIRELESS = [{"wireless": {
    "radio": {
        "24": {"enable": 1, "current_channel": 9, "current_bandwidth": 20, "standard": "11bgn"},
        "5": {"enable": 1, "current_channel": 100, "current_bandwidth": 160, "standard": "11ac"},
        "6": {"enable": 1, "current_channel": 69, "current_bandwidth": 320, "standard": "11ax"},
    },
    "ssid": {
        "24": {"id": "Bbox-X", "security": {"protocol": "WPA2", "passphrase": "secret"}},
        "5": {"id": "Bbox-X", "security": {"protocol": "WPA2", "passphrase": "secret"}},
        "6": {"id": "Bbox-X", "security": {"protocol": "WPA3", "passphrase": "secret"}},
        "mlo": {"enable": 1, "id": "Bbox-X-Plus", "security": {"protocol": "WPA3"}},
    },
    "unified": 1,
}}]


def _wh(mac, ap="Bbox", link="Wifi 5", rssi=-50, active=True):
    return {"mac": mac, "wifi": True, "active": active, "ap": ap, "link": link, "rssi": rssi, "rate": 400}


class WifiTest(unittest.TestCase):
    def test_band_of(self):
        from app.wifi import band_of
        self.assertEqual([band_of(x) for x in ("Wifi 2.4", "Wifi 5", "Wifi 6", "Wifi MLO", "Ethernet", None)],
                         ["2.4", "5", "6", "MLO", None, None])

    def test_parse_radios_and_recommendations(self):
        from app import wifi
        cfg = wifi.parse_radios(BBOX_WIRELESS)
        self.assertEqual(cfg["bands"]["5"]["channel"], 100)
        self.assertTrue(cfg["bands"]["5"]["dfs"])
        self.assertFalse(cfg["bands"]["6"]["dfs"])
        self.assertNotIn("secret", json.dumps(cfg))              # jamais le mot de passe Wi-Fi
        codes = {r["code"] for r in wifi.recommendations(cfg)}
        self.assertEqual(codes, {"dfs", "width160", "mixed_security", "width320", "channel24"})
        cfg["bands"]["5"].update(channel=36, width=80, dfs=False)
        self.assertNotIn("dfs", {r["code"] for r in wifi.recommendations(cfg)})
        self.assertIsNone(wifi.parse_radios({"exception": {}}))
        self.assertEqual(wifi.recommendations(None), [])

    def test_channel_change_detection(self):
        from app import wifi
        cfg = wifi.parse_radios(BBOX_WIRELESS)
        old = json.dumps({"24": 9, "5": 36, "6": 69})
        self.assertEqual(wifi.radios_changed(old, cfg), [("5", 36, 100)])
        self.assertEqual(wifi.radios_changed(None, cfg), [])      # premier relevé : rien à comparer

    def test_sessions_drop_roam_band_gap(self):
        from app.wifi import WifiTracker
        db = DB(":memory:")
        tr = WifiTracker(db)
        a = "aa:aa:aa:aa:aa:01"
        self.assertEqual(tr.update([_wh(a, rssi=-60)], 1000)["opened"], 1)
        tr.update([_wh(a, rssi=-72)], 1060)
        tr.update([_wh(a, rssi=-80)], 1120)
        # disparition : coupure (« drop »), terminée au dernier relevé où il était vu
        self.assertEqual(tr.update([], 1180)["drops"], 1)
        s = db.q("SELECT * FROM wifi_sessions")[0]
        self.assertEqual((s["start"], s["end"], s["end_reason"], s["rssi_last"], s["rssi_min"], s["samples"]),
                         (1000, 1120, "drop", -80, -80, 3))
        # retour sur un répéteur, puis bascule de bande, puis retour sur la box
        tr.update([_wh(a, ap="Répéteur 8070")], 1240)
        self.assertEqual(tr.update([_wh(a, ap="Répéteur 8070", link="Wifi 2.4")], 1300)["bands"], 1)
        self.assertEqual(tr.update([_wh(a, ap="Bbox", link="Wifi 2.4")], 1360)["roams"], 1)
        # NetWatch n'a rien relevé pendant 10 min : on ne compte pas de coupure
        st = tr.update([_wh(a)], 1960)
        self.assertEqual(st["drops"], 0)
        reasons = [r["end_reason"] for r in db.q("SELECT end_reason FROM wifi_sessions ORDER BY id")]
        self.assertEqual(reasons, ["drop", "band", "roam", "gap", None])
        # un appareil inactif ou filaire n'ouvre pas de session
        tr.update([_wh("aa:aa:aa:aa:aa:02", active=False), {"mac": "aa:aa:aa:aa:aa:03", "wifi": False,
                                                            "active": True}], 2020)
        self.assertEqual(db.q1("SELECT COUNT(*) AS n FROM wifi_sessions WHERE mac LIKE 'aa:aa:aa:aa:aa:0_' "
                               "AND mac != ?", [a])["n"], 0)

    def test_sessions_survive_restart(self):
        from app.wifi import WifiTracker
        db = DB(":memory:")
        a = "aa:aa:aa:aa:aa:01"
        WifiTracker(db).update([_wh(a)], 1000)
        tr2 = WifiTracker(db)                                    # redémarrage de NetWatch
        self.assertIn(a, tr2.open)
        tr2.update([_wh(a)], 1060)
        self.assertEqual(db.q1("SELECT COUNT(*) AS n FROM wifi_sessions")["n"], 1)   # même session

    def _fill(self, db, mac, drops, rssi_drop, minutes=600):
        """Appareil connecté `minutes` min avec `drops` coupures, signal `rssi_drop` juste avant chacune."""
        from app.wifi import WifiTracker
        tr, t = WifiTracker(db), 100000
        per = minutes // (drops + 1)
        for k in range(drops + 1):
            for i in range(per):
                tr.update([_wh(mac, rssi=rssi_drop if i == per - 1 else -50)], t)
                t += 60
            if k < drops:                      # la dernière période n'est pas suivie d'une coupure
                tr.update([], t)
                t += 60
        tr._close(mac, t - 60, "gap")          # clôture propre : ne pas fausser les appareils suivants
        return t

    def test_report_verdicts(self):
        from app import wifi
        db = DB(":memory:")
        end = self._fill(db, "aa:aa:aa:aa:aa:01", drops=12, rssi_drop=-82)
        self._fill(db, "aa:aa:aa:aa:aa:02", drops=12, rssi_drop=-45)
        self._fill(db, "aa:aa:aa:aa:aa:03", drops=0, rssi_drop=-50)
        rep = wifi.report(db, 100000, end + 60, {"aa:aa:aa:aa:aa:01": "tablette"})
        by = {d["mac"]: d for d in rep["devices"]}
        self.assertEqual(by["aa:aa:aa:aa:aa:01"]["name"], "tablette")
        self.assertEqual(by["aa:aa:aa:aa:aa:01"]["issues"][0]["code"], "coverage")
        self.assertEqual(by["aa:aa:aa:aa:aa:01"]["worst"], "critical")
        self.assertEqual(by["aa:aa:aa:aa:aa:02"]["issues"][0]["code"], "settings")   # bon signal : pas la portée
        self.assertEqual(by["aa:aa:aa:aa:aa:03"]["issues"][0]["code"], "ok")
        self.assertEqual(rep["devices"][-1]["mac"], "aa:aa:aa:aa:aa:03")             # les plus touchés d'abord
        self.assertEqual(by["aa:aa:aa:aa:aa:01"]["drops"], 12)
        d = wifi.device_detail(db, "aa:aa:aa:aa:aa:01", 100000, end, 600)
        self.assertTrue(d["series"] and d["sessions"])

    def test_issues_edge_cases(self):
        from app import wifi
        base = {"connected_s": 7200, "drops": 0, "roams": 0, "bands": 0, "rssi_avg": -50, "rssi_at_drop": None,
                "ping_up": None}
        self.assertEqual(wifi.issues({**base, "connected_s": 60}, 1)[0]["code"], "no_data")
        codes = lambda **kw: [i["code"] for i in wifi.issues({**base, **kw}, 1)]       # noqa: E731
        self.assertEqual(codes(roams=25), ["pingpong"])
        self.assertEqual(codes(bands=25), ["bandflip"])
        self.assertEqual(codes(rssi_avg=-80), ["weak"])
        self.assertEqual(codes(ping_up=0.5), ["unreachable"])
        self.assertEqual(codes(drops=7), ["ok"])                                       # sous le seuil

    def test_session_reused_between_polls(self):
        """Une seule connexion à la box pour plusieurs relevés (sinon le journal de la box se remplit)."""
        mon, db, _ = bbox_monitor()
        mon.set_credentials("bon")
        for _ in range(3):
            snap = asyncio.run(mon.poll())
        self.assertEqual(FakeBboxProvider.state["logins"], 1)
        self.assertEqual(snap["radios"]["bands"]["5"]["channel"], 100)
        self.assertIn("dfs", [r["code"] for r in mon.status()["wifi"]["recommendations"]])
        # le tracker a vu l'appareil Wi-Fi actif de la box
        self.assertEqual(db.q1("SELECT COUNT(*) AS n FROM wifi_sessions WHERE end IS NULL")["n"], 1)
        mon.set_credentials("bon")                           # changement de mot de passe : nouvelle session
        asyncio.run(mon.poll())
        self.assertEqual(FakeBboxProvider.state["logins"], 2)

    def test_wifi_api(self):
        from starlette.testclient import TestClient

        from app.api import create_app
        from app.engine import Engine
        cfg = Config()
        cfg.demo = True
        cfg.no_auth = True
        db = DB(os.path.join(tempfile.mkdtemp(), "w.db"))
        eng = Engine(cfg, db)
        mac, t = "aa:bb:cc:dd:ee:01", int(__import__("time").time()) - 7200
        for i in range(90):
            eng.box.tracker.update([_wh(mac, rssi=-60)] if i % 30 < 25 else [], t + i * 60)
        eng.box.radios = __import__("app.wifi", fromlist=["x"]).parse_radios(BBOX_WIRELESS)
        with TestClient(create_app(cfg, db, eng)) as c:
            r = c.get("/api/box/wifi?range=24h").json()
            self.assertEqual(r["devices"][0]["mac"], mac)
            self.assertGreaterEqual(r["devices"][0]["drops"], 2)
            self.assertIn("dfs", [x["code"] for x in r["recommendations"]])
            self.assertEqual(r["radios"]["bands"]["5"]["channel"], 100)
            d = c.get(f"/api/box/wifi/{mac}?range=24h").json()
            self.assertTrue(d["sessions"])
            self.assertEqual(c.get("/api/box/wifi/pas-une-mac").status_code, 400)

    def test_channel_event(self):
        events = []

        async def emit(type_, message, device=None, severity="info", data=None, notify=True):
            events.append((type_, severity, message))

        mon, db, _ = bbox_monitor(emit=emit)
        from app import wifi
        cfg5 = wifi.parse_radios(BBOX_WIRELESS)
        asyncio.run(mon._detect_channels(cfg5))
        self.assertEqual(events, [])
        cfg5["bands"]["5"]["channel"] = 36
        asyncio.run(mon._detect_channels(cfg5))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "wifi_channel")
        self.assertIn("100 → 36", events[0][2])


if __name__ == "__main__":
    unittest.main()


NETSH = """
Nom de l'interface : Wi-Fi
SSID 1 : Maison
    BSSID 1                 : 02:00:00:da:81:6b
         Signal             : 75%
         Type de radio         : 802.11be
         Bande               : 2,4 GHz
         Canal            : 11
         Utilisation du canal :        87 (34 %)
         Stations connectées :         2
         Points d'accès colocalisés : 1
            BSSID : 02:00:00:da:81:6f,  Bande : 5 GHz,  Canal : 36
    BSSID 2                 : 3a:00:00:0d:80:76
         Signal             : 89%
         Bande               : 2,4 GHz
         Canal            : 8
SSID 2 : Voisin
    BSSID 1                 : 02:00:00:7c:1b:e4
         Signal             : 31%
         Bande               : 5 GHz
         Canal            : 44
"""


class AirScanTest(unittest.TestCase):
    def test_parse_and_analyze(self):
        from app import airscan
        aps = airscan.parse_networks(NETSH)
        self.assertEqual([(a["channel"], a["band"]) for a in aps], [(11, "2.4"), (8, "2.4"), (44, "5")])
        self.assertEqual(aps[0]["util"], 34)          # le « BSSID : » colocalisé n'est pas un point d'accès
        snap = {"ts": int(time.time()), "aps": aps}
        r = airscan.analyze(snap, wifi_ch=11, zb_ch=20)
        zb = {z["channel"]: z for z in r["zigbee"]}
        self.assertGreater(zb[23]["score"], 0)         # Wi-Fi 8 recouvre Zigbee 21-23
        self.assertEqual(zb[26]["score"], 0)           # canal 26 : au-dessus du Wi-Fi 11
        self.assertEqual(r["best_zigbee"], 26)
        self.assertEqual(r["counts"], {"2.4": 2, "5": 1, "6": 0})
        with self.assertRaises(ValueError):
            airscan.ingest(DB(":memory:"), "rien")


# ------------------------------------------------------------------ fournisseurs de box (Free, Orange, SFR)
async def _noemit(*a, **k):
    return None


class FakeHttp:
    """Remplace boxes.base.Http : des routes (méthode, chemin) → (statut, corps) et un journal des appels."""

    def __init__(self, routes):
        self.routes, self.calls, self.timeout = routes, [], 1.0
        self.authenticated = False

    def _answer(self, method, path, kw):
        self.calls.append((method, path, kw))
        key = (method, path)
        if key not in self.routes:
            key = next((k for k in self.routes if k[0] == method and path.startswith(k[1])), None)
        if key is None:
            return 404, None
        res = self.routes[key]
        return res(kw) if callable(res) else res

    def json(self, method, path="", **kw):
        return self._answer(method, path, kw)

    def request(self, method, path="", **kw):
        status, body = self._answer(method, path, kw)
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        return status, (body or "").encode() if isinstance(body, str) else (body or b"")


def fbx(result, **extra):
    return 200, {"success": True, "result": result, **extra}


FREEBOX_HOSTS = [
    {"id": "ether-aa:bb:cc:dd:ee:01", "primary_name": "salon-tv", "host_type": "television", "active": True,
     "last_activity": 1, "l2ident": {"id": "AA:BB:CC:DD:EE:01", "type": "mac_address"},
     "l3connectivities": [{"addr": "192.168.1.20", "af": "ipv4", "active": True}],
     "access_point": {"connectivity_type": "wifi", "type": "repeater", "mac": "AA:BB:CC:00:00:99",
                      "wifi_information": {"band": "5g", "ssid": "Maison", "signal": -61}}},
    {"id": "ether-aa:bb:cc:dd:ee:02", "primary_name": "nas", "host_type": "nas", "active": True,
     "l2ident": {"id": "AA:BB:CC:DD:EE:02", "type": "mac_address"},
     "l3connectivities": [{"addr": "192.168.1.30", "af": "ipv4", "active": True}],
     "access_point": {"connectivity_type": "ethernet"}},
    {"id": "ether-aa:bb:cc:dd:ee:03", "primary_name": "tel", "active": True,
     "l2ident": {"id": "AA:BB:CC:DD:EE:03", "type": "mac_address"},
     "l3connectivities": [{"addr": "192.168.1.31", "af": "ipv4", "active": True}],
     "access_point": {"connectivity_type": "wifi", "wifi_information": {"band": "2d4g", "ssid": "Maison",
                                                                        "signal": -70}}},
    {"id": "ether-aa:bb:cc:00:00:99", "primary_name": "Répéteur salon", "active": True,
     "l2ident": {"id": "AA:BB:CC:00:00:99", "type": "mac_address"}, "l3connectivities": []},
]


def freebox_http(granted="granted", password_ok=True):
    import hashlib
    import hmac

    def session(kw):
        pw = hmac.new(b"TOK", b"chal", hashlib.sha1).hexdigest()
        if kw["json_body"]["password"] != pw or not password_ok:
            return 403, {"success": False, "error_code": "invalid_token", "msg": "bad"}
        return fbx({"session_token": "SESS"})

    routes = {
        ("GET", "/api_version"): (200, {"device_name": "Freebox Server", "api_version": "13.0",
                                        "box_model_name": "Freebox v9 (r1)"}),
        ("POST", "/api/latest/login/authorize/"): fbx({"app_token": "TOK", "track_id": 7}),
        ("GET", "/api/latest/login/authorize/7"): fbx({"status": granted}),
        ("GET", "/api/latest/login/"): fbx({"challenge": "chal"}),
        ("POST", "/api/latest/login/session/"): session,
        ("GET", "/api/latest/system/"): fbx({"firmware_version": "4.8.1", "uptime_val": 5000,
                                              "model_info": {"pretty_name": "Freebox Server (r2)"}}),
        ("GET", "/api/latest/connection/"): fbx({
            "state": "up", "media": "ftth", "ipv4": "82.1.2.3", "ipv6": "2a01::1", "bytes_down": 9000,
            "bytes_up": 3000, "rate_down": 125000, "rate_up": 12500, "bandwidth_down": 1000000000,
            "bandwidth_up": 600000000}),
        ("GET", "/api/latest/lan/browser/pub/"): fbx(FREEBOX_HOSTS),
        ("GET", "/api/latest/wifi/ap/"): fbx([
            {"id": 0, "config": {"band": "2g4"}, "status": {"state": "active", "primary_channel": 6,
                                                            "channel_width": "20"}},
            {"id": 1, "config": {"band": "5g"}, "status": {"state": "active", "primary_channel": 100,
                                                           "channel_width": "80"}}]),
        ("GET", "/api/latest/wifi/bss/"): fbx([
            {"phy_id": 0, "config": {"ssid": "Maison", "encryption": "wpa2_psk"}},
            {"phy_id": 1, "config": {"ssid": "Maison", "encryption": "wpa2_psk"}}]),
    }
    return FakeHttp(routes)


class FreeboxTest(unittest.TestCase):
    def test_probe_and_collect(self):
        from app.boxes.freebox import FreeboxProvider
        self.assertEqual(FreeboxProvider.probe("192.168.1.254", freebox_http())["model"], "Freebox v9 (r1)")
        self.assertIsNone(FreeboxProvider.probe("192.168.1.254", FakeHttp({})))
        p = FreeboxProvider("192.168.1.254", freebox_http())
        snap = p.collect({"token": "TOK"})
        self.assertEqual(snap["device"]["model"], "Freebox Server (r2)")
        self.assertTrue(snap["device"]["ftth"])
        self.assertTrue(snap["summary"]["internet_up"])
        self.assertEqual((snap["stats"]["rx_kbps"], snap["stats"]["tx_kbps"]), (1000, 100))   # octets/s → kbit/s
        self.assertEqual(snap["stats"]["rx_contract_kbps"], 1000000)
        tv = next(h for h in snap["hosts"] if h["hostname"] == "salon-tv")
        self.assertEqual((tv["link"], tv["rssi"], tv["ap"], tv["ap_kind"]), ("Wifi 5", -61, "Répéteur salon", "repeater"))
        self.assertEqual(next(h for h in snap["hosts"] if h["hostname"] == "tel")["link"], "Wifi 2.4")
        nas = next(h for h in snap["hosts"] if h["hostname"] == "nas")
        self.assertEqual((nas["wifi"], nas["ap"]), (False, "Freebox"))
        self.assertEqual([r["label"] for r in snap["repeaters"]], ["Répéteur salon"])
        self.assertTrue(snap["radios"]["bands"]["5"]["dfs"])
        self.assertEqual(snap["radios"]["bands"]["5"]["security"], "WPA2")

    def test_auth_errors(self):
        from app.boxes import BoxApprovalRequired, BoxAuthError
        from app.boxes.freebox import FreeboxProvider
        with self.assertRaises(BoxApprovalRequired):
            FreeboxProvider("192.168.1.254", freebox_http()).collect({})
        with self.assertRaises(BoxAuthError):
            FreeboxProvider("192.168.1.254", freebox_http(password_ok=False)).collect({"token": "TOK"})

    def test_monitor_approval_flow(self):
        from app.box import BoxMonitor
        from app.boxes.freebox import FreeboxProvider
        from app.vault import Vault
        cfg, db = Config(), DB(":memory:")
        cfg.box_enabled = True
        mon = BoxMonitor(cfg, db, Vault(db, "clé-de-test-longue", "/tmp/nw-unused.key"), _noemit,
                         gateway=lambda: "192.168.1.254")
        http = freebox_http()
        mon._factory = lambda pid, host: FreeboxProvider(host, http)
        mon.set_provider("freebox")
        self.assertIsNone(asyncio.run(mon.poll()))                  # pas encore autorisé
        self.assertTrue(mon.status()["needs_approval"])
        self.assertFalse(mon.has_credentials())
        asyncio.run(mon.start_approval())
        self.assertEqual(asyncio.run(mon.approval_status())["status"], "granted")
        self.assertTrue(mon.has_credentials())
        self.assertNotIn("TOK", db.get_meta("box_token"))           # jeton chiffré au repos
        snap = asyncio.run(mon.poll())
        self.assertEqual(len(snap["hosts"]), 4)
        self.assertFalse(mon.status()["needs_approval"])
        self.assertNotIn("token", json.dumps(mon.status()).lower().replace("has_token", ""))


LIVEBOX_DEVICES = {"status": [
    {"Key": "AA:BB:CC:DD:EE:01", "Name": "tv", "Active": True, "IPAddress": "192.168.1.20",
     "PhysAddress": "AA:BB:CC:DD:EE:01", "InterfaceName": "wl1", "Tags": "lan edev mac wifi", "SignalStrength": -58},
    {"Key": "AA:BB:CC:DD:EE:02", "Name": "pc", "Active": False, "IPAddress": "192.168.1.30",
     "PhysAddress": "AA:BB:CC:DD:EE:02", "InterfaceName": "eth1", "Tags": "lan edev mac ethernet"},
]}


def livebox_http(login_ok=True):
    def ws(kw):
        body = kw["json_body"]
        key = (body["service"], body["method"])
        if key == ("sah.Device.Information", "createContext"):
            if not login_ok or body["parameters"]["password"] != "bon":
                return 200, {"status": 13, "errors": [{"error": 13}]}
            return 200, {"status": 0, "data": {"contextID": "CTX", "groups": "admin"}}
        if kw["headers"].get("X-Context") != "CTX":
            return 401, None
        return 200, {
            ("DeviceInfo", "get"): {"status": {"ProductClass": "Livebox 6", "SoftwareVersion": "SG30", "UpTime": 4000,
                                               "NumberOfReboots": 3}},
            ("NMC", "getWANStatus"): {"status": True, "data": {"WanState": "up", "LinkType": "ftth",
                                                                "IPAddress": "90.1.2.3", "RemoteGateway": "90.1.0.1"}},
            ("NeMo.Intf.data", "getNetDevStats"): {"status": {"RxBytes": 5000, "TxBytes": 700}},
            ("Devices", "get"): LIVEBOX_DEVICES,
        }[key]
    return FakeHttp({("POST", "/ws"): ws, ("GET", "/"): (200, "<html><title>Livebox</title></html>")})


class LiveboxTest(unittest.TestCase):
    def test_collect(self):
        from app.boxes.livebox import LiveboxProvider
        self.assertEqual(LiveboxProvider.probe("192.168.1.1", livebox_http())["model"], "Livebox")
        p = LiveboxProvider("192.168.1.1", livebox_http())
        snap = p.collect({"username": "admin", "password": "bon"})
        self.assertEqual((snap["device"]["model"], snap["device"]["boots"]), ("Livebox 6", 3))
        self.assertTrue(snap["summary"]["internet_up"] and snap["device"]["ftth"])
        self.assertEqual(snap["wan"]["ip"], "90.1.2.3")
        self.assertEqual(snap["stats"]["rx_bytes"], 5000)
        tv, pc = snap["hosts"]
        self.assertEqual((tv["link"], tv["rssi"], tv["wifi"], tv["active"]), ("Wifi 5", -58, True, True))
        self.assertEqual((pc["link"], pc["wifi"], pc["ap"]), ("Ethernet", False, "Livebox"))

    def test_wrong_password(self):
        from app.boxes.livebox import LiveboxProvider
        snap = LiveboxProvider("192.168.1.1", livebox_http()).collect({"username": "admin", "password": "faux"})
        self.assertIn("refusé", snap["auth_error"])
        self.assertIsNone(snap["hosts"])


SFR_SYSTEM = '<?xml version="1.0"?><rsp stat="ok" version="1.0"><system product_id="NB6VAC" ' \
             'version_mainfirmware="NB6VAC-MAIN-R4.0.45" uptime="9000"/></rsp>'
SFR_WAN = '<rsp stat="ok"><wan status="up" ip_addr="88.1.2.3" infra="ftth" mode="ftth/routed"/></rsp>'
SFR_HOSTS = ('<rsp stat="ok"><hostsList><host type="pc" name="tv" ip="192.168.1.20" mac="AA:BB:CC:DD:EE:01" '
             'iface="wlan0" alive="1" status="online"/><host type="nas" name="nas" ip="192.168.1.30" '
             'mac="AA:BB:CC:DD:EE:02" iface="lan1" alive="0" status="offline"/></hostsList></rsp>')
SFR_WLAN = '<rsp stat="ok"><wlan><client mac_addr="AA:BB:CC:DD:EE:01" rssi="-60" wifi_band="5"/></wlan></rsp>'


def sfr_http(password="bon"):
    from app.boxes.sfr import compute_hash

    def api(kw, path):
        m = dict(p.split("=", 1) for p in path.split("?", 1)[1].split("&"))
        method = m["method"]
        if method == "system.getInfo":
            return 200, SFR_SYSTEM
        if method == "wan.getInfo":
            return 200, SFR_WAN
        if method == "auth.getToken":
            return 200, '<rsp stat="ok"><auth token="T1" method="all"/></rsp>'
        if method == "auth.checkToken":
            ok = m["token"] == "T1" and m["hash"] == compute_hash("T1", "admin", password)
            return 200, '<rsp stat="ok"><auth token="T2"/></rsp>' if ok else \
                '<rsp stat="fail"><err code="204" msg="bad"/></rsp>'
        if m.get("token") != "T2":
            return 200, '<rsp stat="fail"><err code="115" msg="auth"/></rsp>'
        return 200, {"lan.getHostsList": SFR_HOSTS, "wlan.getClientList": SFR_WLAN}[method]

    class H(FakeHttp):
        def request(self, method, path="", **kw):
            status, body = api(kw, path)
            return status, body.encode()
    return H({})


class SfrTest(unittest.TestCase):
    def test_hash_and_collect(self):
        from app.boxes.sfr import SfrProvider, compute_hash
        h = compute_hash("tok", "admin", "pw")
        self.assertEqual(len(h), 128)
        self.assertNotEqual(h[:64], h[64:])
        self.assertEqual(SfrProvider.probe("192.168.1.1", sfr_http())["model"], "NB6VAC")
        snap = SfrProvider("192.168.1.1", sfr_http()).collect({"username": "admin", "password": "bon"})
        self.assertEqual((snap["device"]["model"], snap["device"]["uptime"]), ("NB6VAC", 9000))
        self.assertTrue(snap["summary"]["internet_up"] and snap["device"]["ftth"])
        tv, nas = snap["hosts"]
        self.assertEqual((tv["link"], tv["rssi"], tv["active"]), ("Wifi 5", -60, True))
        self.assertEqual((nas["link"], nas["active"], nas["ap"]), ("Ethernet", False, "Box SFR"))

    def test_wrong_password_and_public_only(self):
        from app.boxes.sfr import SfrProvider
        snap = SfrProvider("192.168.1.1", sfr_http()).collect({"username": "admin", "password": "faux"})
        self.assertTrue(snap["auth_error"])
        self.assertEqual(snap["device"]["model"], "NB6VAC")          # les données publiques restent exploitables
        snap = SfrProvider("192.168.1.1", sfr_http()).collect({})
        self.assertIsNone(snap["hosts"])
        self.assertIsNone(snap["auth_error"])


class BoxSetupTest(unittest.TestCase):
    def test_detect_picks_matching_provider(self):
        from app import boxes
        calls = []

        class Hit(boxes.BoxProvider):
            id, label = "hit", "Hit"

            @classmethod
            def probe(cls, host, http=None):
                calls.append(host)
                return {"model": "M"}

        class Miss(Hit):
            id = "miss"

            @classmethod
            def probe(cls, host, http=None):
                return None

        old = dict(boxes.PROVIDERS)
        boxes.PROVIDERS.clear()
        boxes.PROVIDERS.update({"hit": Hit, "miss": Miss})
        try:
            self.assertEqual([r["provider"] for r in boxes.detect("192.168.1.1")], ["hit"])
            self.assertEqual(boxes.detect("8.8.8.8"), [])                  # jamais hors du LAN
        finally:
            boxes.PROVIDERS.clear()
            boxes.PROVIDERS.update(old)

    def test_legacy_migration_and_settings_alias(self):
        from app import settings
        from app.box import BoxMonitor
        from app.vault import Vault
        cfg, db = Config(), DB(":memory:")
        db.set_meta("bbox_password", "chiffré")
        db.set_meta("cfg:bbox_enabled", "1")
        db.set_meta("cfg:bbox_interval", "120")
        mon = BoxMonitor(cfg, db, Vault(db, "clé-de-test-longue", "/tmp/nw-unused.key"), _noemit)
        self.assertEqual((db.get_meta("box_password"), mon.provider_id()), ("chiffré", "bouygues"))
        settings.load_overrides(cfg, db)
        self.assertEqual((cfg.box_enabled, cfg.box_interval), (True, 120))

    def test_wizard_api(self):
        from starlette.testclient import TestClient

        from app.api import create_app
        from app.engine import Engine
        cfg = Config()
        cfg.demo = True
        cfg.no_auth = True
        db = DB(os.path.join(tempfile.mkdtemp(), "wz.db"))
        eng = Engine(cfg, db)
        with TestClient(create_app(cfg, db, eng)) as c:
            self.assertTrue(c.get("/api/wizard").json()["done"])            # installation existante : pas imposé
            c.post("/api/wizard/reset")
            w = c.get("/api/wizard").json()
            self.assertFalse(w["done"])
            self.assertEqual({p["id"] for p in w["box"]["providers"]}, {"bouygues", "freebox", "livebox", "sfr"})
            self.assertIn("scans_enabled", w["settings"])
            self.assertTrue(c.get("/api/session").json()["wizard_required"])
            r = c.patch("/api/settings", json={"deep_enabled": False, "diag_enabled": False, "wifi_tracking": False})
            self.assertEqual(r.json()["errors"], {})
            self.assertFalse(cfg.deep_enabled or cfg.diag_enabled or cfg.wifi_tracking)
            c.post("/api/wizard/complete")
            self.assertFalse(c.get("/api/session").json()["wizard_required"])


# ------------------------------------------------------------------ sécurité
class SecurityHardeningTest(unittest.TestCase):
    def app(self, **over):
        from starlette.testclient import TestClient

        from app.api import create_app
        from app.engine import Engine
        cfg = Config()
        cfg.demo = True
        cfg.data_dir = tempfile.mkdtemp()
        for k, v in over.items():
            setattr(cfg, k, v)
        db = DB(os.path.join(cfg.data_dir, "s.db"))
        eng = Engine(cfg, db)
        return TestClient(create_app(cfg, db, eng)), cfg, db, eng

    def test_vault_aes256_and_legacy_upgrade(self):
        from cryptography.fernet import Fernet

        from app.vault import Vault, VaultError, derive_key
        db = DB(":memory:")
        v = Vault(db, "une-phrase-secrète-assez-longue", "/tmp/nw-unused.key")
        tok = v.encrypt("s3cret")
        self.assertTrue(tok.startswith("v2:"))
        self.assertNotEqual(tok, v.encrypt("s3cret"))                 # nonce aléatoire à chaque chiffrement
        self.assertEqual(v.decrypt(tok), "s3cret")
        with self.assertRaises(VaultError):                           # jeton altéré : rejeté (chiffrement authentifié)
            v.decrypt(tok[:-4] + ("AAAA" if not tok.endswith("AAAA") else "BBBB"))
        # un secret écrit par une ancienne version (Fernet) est relu puis rechiffré au démarrage
        legacy = Fernet(derive_key("une-phrase-secrète-assez-longue", bytes.fromhex(db.get_meta("vault_salt"))))
        db.set_meta("box_password", legacy.encrypt(b"ancien").decode())
        v2 = Vault(db, "une-phrase-secrète-assez-longue", "/tmp/nw-unused.key")
        self.assertTrue(db.get_meta("box_password").startswith("v2:"))
        self.assertEqual(v2.decrypt(db.get_meta("box_password")), "ancien")
        self.assertTrue(Vault(db, "une-autre-phrase-secrète-longue", "/tmp/nw-unused.key").locked)

    def test_sessions_are_hashed_and_legacy_migrated(self):
        from app.auth import Auth, token_hash
        cfg, db = Config(), DB(":memory:")
        cfg.password = "motdepasse-test"
        db.x("INSERT INTO sessions(token, username, created, expires, ip) VALUES(?,?,?,?,?)",
             ["ancien-jeton-en-clair", "admin", 0, int(time.time()) + 3600, "x"])
        a = Auth(cfg, db)
        self.assertEqual(a.validate_session("ancien-jeton-en-clair"), "admin")      # la session existante survit
        tok, _ = a.create_session("1.2.3.4")
        stored = {r["token"] for r in db.q("SELECT token FROM sessions")}
        self.assertEqual(stored, {token_hash(tok), token_hash("ancien-jeton-en-clair")})
        self.assertIsNone(a.validate_session(token_hash(tok)))                      # l'empreinte volée ne sert à rien

    def test_password_hash_is_strengthened_on_login(self):
        from app import auth
        cfg, db = Config(), DB(":memory:")
        a = auth.Auth(cfg, db)
        db.set_meta("auth_user", "admin")
        db.set_meta("auth_hash", auth.hash_password("motdepasse-test", n=2**12))    # ancienne empreinte, plus faible
        self.assertTrue(a.check_credentials("admin", "motdepasse-test"))
        self.assertIn(f"${auth.SCRYPT_N}$", db.get_meta("auth_hash"))
        self.assertFalse(a.check_credentials("admin", "x" * 5000))                  # démesuré : refusé sans hachage

    def test_basic_auth_is_rate_limited_and_xff_not_trusted(self):
        c, cfg, _, _ = self.app(password="motdepasse-test")
        with c:
            self.assertEqual(c.get("/api/overview").status_code, 401)
            self.assertEqual(c.get("/api/overview", auth=("admin", "motdepasse-test")).status_code, 200)
            # chaque essai annonce une adresse différente : sans proxy de confiance, c'est ignoré
            codes = [c.get("/api/overview", auth=("admin", f"faux{i}"),
                           headers={"X-Forwarded-For": f"10.0.0.{i}"}).status_code for i in range(7)]
            self.assertEqual(codes[:5], [401] * 5)
            self.assertEqual(codes[5:], [429, 429])
            self.assertEqual(c.post("/api/login", json={"username": "admin", "password": "motdepasse-test"}).status_code, 429)

    def test_trusted_proxy_forwarded_address(self):
        c, cfg, _, _ = self.app(password="motdepasse-test", trusted_proxies=["testclient", "10.9.0.0/16"])
        # TestClient se présente comme « testclient » (pas une IP) : jamais de confiance
        with c:
            for i in range(5):
                c.post("/api/login", json={"username": "admin", "password": "faux"},
                       headers={"X-Forwarded-For": "203.0.113.7"})
            r = c.post("/api/login", json={"username": "admin", "password": "motdepasse-test"},
                       headers={"X-Forwarded-For": "198.51.100.1"})
            self.assertEqual(r.status_code, 429)

    def test_http_hardening(self):
        c, _, _, _ = self.app(no_auth=True)
        with c:
            r = c.get("/")
            self.assertIn("script-src 'self'", r.headers["content-security-policy"])
            self.assertEqual(r.headers["x-frame-options"], "DENY")
            self.assertEqual(r.headers["x-content-type-options"], "nosniff")
            self.assertNotIn("<script>", r.text)                              # aucun script en ligne
            self.assertEqual(c.get("/api/overview").headers["referrer-policy"], "no-referrer")
            big = "x" * 1_100_000
            self.assertEqual(c.patch("/api/settings", content=big).status_code, 413)
            r = c.post("/api/wizard/reset", headers={"Sec-Fetch-Site": "cross-site"})
            self.assertEqual(r.status_code, 403)                              # écriture depuis un autre site
            self.assertEqual(c.post("/api/wizard/reset", headers={"Sec-Fetch-Site": "same-origin"}).status_code, 200)
            self.assertEqual(c.get("/api/events?limit=-5").status_code, 200)
            self.assertEqual(c.get("/api/events?limit=abc").status_code, 200)

    def test_frame_ancestors_setting(self):
        c, _, _, _ = self.app(no_auth=True, frame_ancestors="https://ha.exemple.fr")
        with c:
            r = c.get("/")
            self.assertIn("frame-ancestors 'self' https://ha.exemple.fr", r.headers["content-security-policy"])
            self.assertNotIn("x-frame-options", r.headers)

    def test_settings_guardrails(self):
        from app import settings
        cfg, db = Config(), DB(":memory:")
        bad = {"discovery_interval": 1, "ping_count": 500, "nmap_concurrency": 64, "box_interval": 1,
               "nmap_args": "-sS --script=http-shellshock", "external_targets": "a b;rm",
               "z2m_topic": "#", "ha_url": "https://evil.example.com", "box_host": "8.8.8.8",
               "bufferbloat_url": "file:///etc/passwd", "diag_tcp_targets": "1.1.1.1:99999"}
        res = settings.apply(cfg, db, bad)
        self.assertEqual(set(res["errors"]), set(bad))
        self.assertEqual(res["applied"], {})
        self.assertEqual(cfg.discovery_interval, 60)
        ok = settings.apply(cfg, db, {"discovery_interval": 120, "nmap_args": "-sT -p 22,80,443 -T3",
                                      "external_targets": "1.1.1.1, example.com"})
        self.assertEqual(ok["errors"], {})
        # une valeur hors bornes venue d'ailleurs (variable d'environnement, ancienne base) est ramenée dans les bornes
        cfg.discovery_interval, cfg.nmap_concurrency, cfg.nmap_args = 0, 500, "-iL /etc/shadow"
        settings.sanitize(cfg)
        self.assertEqual((cfg.discovery_interval, cfg.nmap_concurrency), (30, 8))
        self.assertIn("-sS", cfg.nmap_args)

    def test_nmap_args_whitelist(self):
        from app.nmapscan import DEFAULT_ARGS, safe_args, scan_host
        self.assertEqual(safe_args(DEFAULT_ARGS)[:2], ["-sS", "-sV"])
        self.assertEqual(safe_args("-p22,80 --max-rate=100"), ["-p", "22,80", "--max-rate", "100"])
        for bad in ("--script vuln", "-oN /data/x", "-iL /etc/passwd", "8.8.8.8", "-T5", "-sS; reboot",
                    "--max-rate 100000", "-S 1.2.3.4", "--top-ports"):
            with self.assertRaises(ValueError, msg=bad):
                safe_args(bad)
        self.assertIsNone(asyncio.run(scan_host("192.168.1.1; id", DEFAULT_ARGS)))     # cible non IP : rien n'est lancé

    def test_credential_test_stays_on_lan(self):
        c, _, _, eng = self.app(no_auth=True)
        with c:
            cid = c.post("/api/credentials", json={"name": "t", "username": "root", "secret": "pw",
                                                   "scope": "192.168.1.0/28"}).json()["id"]
            for ip in ("8.8.8.8", "evil.example.com", "192.168.1.200", "10.0.0.5"):
                r = c.post(f"/api/credentials/{cid}/test", json={"ip": ip})
                self.assertEqual(r.status_code, 400, ip)                       # le secret ne quitte pas le LAN / la portée

    def test_push_endpoint_must_be_public_https(self):
        from app.push import endpoint_allowed
        self.assertTrue(endpoint_allowed("https://fcm.googleapis.com/fcm/send/abc"))
        for bad in ("http://fcm.googleapis.com/x", "https://192.168.1.1/x", "https://127.0.0.1/", "https://nas.local/x",
                    "https://localhost/x", "ftp://x.com", "https://user:pw@x.com/"):
            self.assertFalse(endpoint_allowed(bad), bad)

    def test_ssh_password_only_for_approved_devices(self):
        from app.sshinv import SSHInventory
        from app.vault import Vault
        cfg, db = Config(), DB(":memory:")
        v = Vault(db, "une-phrase-secrète-assez-longue", "/tmp/nw-unused.key")
        v.create({"name": "mdp", "username": "root", "secret": "pw"})
        v.create({"name": "clé", "username": "root", "auth_type": "key", "secret": "-----BEGIN OPENSSH PRIVATE KEY-----"})
        inv = SSHInventory(cfg, db, v)
        dev = {"id": 1, "ip": "192.168.1.9", "known": 0, "last_deep_scan": None}
        self.assertEqual([c["name"] for c in inv.candidates(dev)], ["clé"])
        self.assertEqual({c["name"] for c in inv.candidates({**dev, "known": 1})}, {"mdp", "clé"})

    def test_database_file_is_private(self):
        path = os.path.join(tempfile.mkdtemp(), "p.db")
        DB(path)
        self.assertEqual(os.stat(path).st_mode & 0o077, 0)

    def test_vapid_key_encrypted_at_rest(self):
        from app.push import PushManager, _AVAILABLE
        from app.vault import Vault
        if not _AVAILABLE:
            self.skipTest("pywebpush absent")
        cfg, db = Config(), DB(":memory:")
        db_plain = "-----BEGIN PRIVATE KEY-----"
        v = Vault(db, "une-phrase-secrète-assez-longue", "/tmp/nw-unused.key")
        p1 = PushManager(cfg, db, v)
        self.assertIsNone(db.get_meta("vapid_private_pem"))
        self.assertNotIn(db_plain, db.get_meta("vapid_private_enc"))
        self.assertEqual(PushManager(cfg, db, v).application_server_key, p1.application_server_key)   # clé stable


class SecurityPass2Test(unittest.TestCase):
    def test_mac_flood_is_bounded(self):
        from app import engine as eng_mod
        from app.engine import Engine
        cfg = Config()
        cfg.external_targets = []
        cfg.data_dir = tempfile.mkdtemp()
        db = DB(":memory:")
        e = Engine(cfg, db)
        e.backend = FakeBackend()
        e.net.ip = e.net.mac = None
        e.backend.hosts = {"192.168.1.10": "aa:bb:cc:00:00:10"}
        asyncio.run(e.discovery_cycle())                       # inventaire initial
        # un attaquant répond à l'ARP avec 300 adresses MAC forgées
        e.backend.hosts = {f"192.168.{1 + i // 250}.{i % 250 + 1}": f"02:00:00:00:{i // 256:02x}:{i % 256:02x}"
                           for i in range(300)}
        asyncio.run(e.discovery_cycle())
        n = db.q1("SELECT COUNT(*) AS n FROM devices WHERE kind='lan'")["n"]
        self.assertEqual(n, 1 + eng_mod.MAX_NEW_PER_CYCLE)
        alerts = db.q("SELECT * FROM events WHERE type='security_finding'")
        self.assertEqual(len(alerts), 1)                       # une seule alerte, pas 275 notifications
        self.assertIn("275", alerts[0]["message"])

    def test_z2m_payloads_are_typed_and_bounded(self):
        from app import z2m
        info = z2m.parse_info(json.dumps({
            "version": "<img src=x onerror=alert(1)>" * 20, "network": {"channel": "<script>", "pan_id": {"a": 1}},
            "coordinator": {"type": ["x"], "meta": "pas-un-objet"}}).encode())
        self.assertIsNone(info["channel"])                     # jamais de texte là où l'interface attend un nombre
        self.assertIsNone(info["pan_id"])
        self.assertIsNone(info["coordinator"])
        self.assertLessEqual(len(info["version"]), 40)
        devs = z2m.parse_devices(json.dumps(
            [{"ieee_address": f"0x{i:016x}", "friendly_name": "n" * 5000, "type": {"x": 1},
              "network_address": "abc", "definition": "texte"} for i in range(3000)]).encode())
        self.assertEqual(len(devs), z2m.MAX_DEVICES)
        self.assertEqual((len(devs[0]["name"]), devs[0]["type"], devs[0]["nwk"]), (120, None, None))

    def test_z2m_log_flood_is_rate_limited(self):
        mon, db, _ = z2m_monitor()
        payload = json.dumps({"level": "error", "message": "delivery failed"}).encode()
        for _ in range(500):
            mon._bridge_log(payload, 1_000_000)
        self.assertEqual(db.q1("SELECT COUNT(*) AS n FROM z2m_log")["n"], 60)

    def test_mqtt_truncated_packet(self):
        from app.mqttsub import MQTTError, parse_publish
        for body in (b"", b"\x00", b"\x00\x05ab"):
            try:
                parse_publish(0x02, body)
            except MQTTError:
                pass                                           # erreur propre : la session est rouverte

    def test_setup_only_from_local_network(self):
        from starlette.testclient import TestClient

        from app.api import create_app
        from app.engine import Engine
        cfg = Config()
        cfg.demo = True
        cfg.data_dir = tempfile.mkdtemp()
        db = DB(os.path.join(cfg.data_dir, "s.db"))
        app = create_app(cfg, db, Engine(cfg, db))
        body = {"username": "admin", "password": "motdepasse-test"}
        with TestClient(app, client=("8.8.8.8", 4000)) as c:          # visiteur venu d'Internet
            self.assertEqual(c.post("/api/setup", json=body).status_code, 403)
        with TestClient(app, client=("192.168.1.50", 4000)) as c:
            self.assertEqual(c.post("/api/setup", json=body).status_code, 200)

    def test_trusted_proxy_resolves_real_visitor(self):
        from starlette.testclient import TestClient

        from app.api import create_app
        from app.engine import Engine
        cfg = Config()
        cfg.demo = True
        cfg.password = "motdepasse-test"
        cfg.trusted_proxies = ["10.9.0.2"]
        cfg.data_dir = tempfile.mkdtemp()
        db = DB(os.path.join(cfg.data_dir, "s.db"))
        app = create_app(cfg, db, Engine(cfg, db))
        bad = {"username": "admin", "password": "faux"}
        good = {"username": "admin", "password": "motdepasse-test"}
        with TestClient(app, client=("10.9.0.2", 4000)) as c:         # le proxy de confiance
            for _ in range(5):
                c.post("/api/login", json=bad, headers={"X-Forwarded-For": "203.0.113.7"})
            # l'attaquant est bloqué, pas les autres visiteurs qui passent par le même proxy
            self.assertEqual(c.post("/api/login", json=good, headers={"X-Forwarded-For": "203.0.113.7"}).status_code, 429)
            self.assertEqual(c.post("/api/login", json=good, headers={"X-Forwarded-For": "198.51.100.1"}).status_code, 200)
            # un en-tête falsifié en amont du proxy ne trompe pas : c'est la dernière adresse non fiable qui compte
            self.assertEqual(c.post("/api/login", json=good,
                                    headers={"X-Forwarded-For": "1.2.3.4, 203.0.113.7"}).status_code, 429)
