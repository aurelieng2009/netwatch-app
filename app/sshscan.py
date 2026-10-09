"""Inventaire authentifié par SSH.

Un seul script shell en lecture seule est exécuté par connexion ; chaque section est
précédée d'un marqueur « @@NW:<nom> ». Les fonctions parse_* sont pures (testables sans
réseau). La clé d'hôte est épinglée au premier contact (TOFU) : si elle change, la
connexion est refusée AVANT l'envoi du mot de passe (protection contre l'interception).
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

log = logging.getLogger("netwatch.ssh")

try:
    import asyncssh
except ImportError:  # pragma: no cover
    asyncssh = None  # type: ignore[assignment]

MARK = "@@NW:"

# Chaque commande est sans effet de bord ; les erreurs sont ignorées (hôtes minimalistes).
SCRIPT = r"""
export LC_ALL=C PATH="$PATH:/sbin:/usr/sbin:/usr/local/bin"
s() { echo "@@NW:$1"; }
s uname; uname -snrm 2>/dev/null
s os_release; cat /etc/os-release 2>/dev/null
s hostname; hostname 2>/dev/null
s uptime; cat /proc/uptime 2>/dev/null
s loadavg; cat /proc/loadavg 2>/dev/null
s cpu; grep -m1 -E '^(model name|Hardware|Model)' /proc/cpuinfo 2>/dev/null; nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null
s meminfo; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null
s df; df -PkT -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null || df -Pk 2>/dev/null
s netdev; cat /proc/net/dev 2>/dev/null
s links; for i in /sys/class/net/*; do n=${i##*/}; k=virt; [ -e "$i/device" ] && k=phys; [ -d "$i/wireless" ] || [ -d "$i/phy80211" ] && k=wifi; echo "$n $(cat $i/speed 2>/dev/null || echo -) $(cat $i/duplex 2>/dev/null || echo -) $(cat $i/operstate 2>/dev/null || echo -) $(cat $i/mtu 2>/dev/null || echo -) $k"; done 2>/dev/null
s wireless; cat /proc/net/wireless 2>/dev/null
s iw; for i in /sys/class/net/*; do [ -d "$i/wireless" ] || [ -d "$i/phy80211" ] || continue; echo "iface ${i##*/}"; iw dev "${i##*/}" link 2>/dev/null; done 2>/dev/null
s ipaddr; ip -o -4 addr show 2>/dev/null
s routes; ip -4 route show default 2>/dev/null
s neigh; ip -4 neigh show 2>/dev/null || cat /proc/net/arp 2>/dev/null
s resolv; grep -E '^nameserver' /etc/resolv.conf 2>/dev/null
s snmp; cat /proc/net/snmp 2>/dev/null
s listen; ss -Htlnu 2>/dev/null || netstat -tlnu 2>/dev/null
s dmi; for f in sys_vendor product_name product_version board_vendor board_name bios_version; do echo "$f=$(cat /sys/class/dmi/id/$f 2>/dev/null)"; done
s devicetree; tr -d '\0' < /proc/device-tree/model 2>/dev/null; echo
s thermal; cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null
s time; timedatectl show -p NTPSynchronized --value 2>/dev/null; echo "epoch=$(date +%s)"
s virt; systemd-detect-virt 2>/dev/null
s pressure; for f in cpu io memory; do echo "$f $(grep '^some' /proc/pressure/$f 2>/dev/null)"; done
s containers; docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null | head -60
"""
SUDO_SCRIPT = r"""
s sudo_dmi; sudo -n dmidecode -s system-serial-number 2>/dev/null; sudo -n dmidecode -t memory 2>/dev/null | grep -E '^\s+(Size|Speed|Type):' | grep -v 'No Module' | head -32
s end
"""


# ------------------------------------------------------------------ parsing
def split_sections(out: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    cur = None
    for line in out.splitlines():
        if line.startswith(MARK):
            cur = line[len(MARK):].strip()
            sections[cur] = []
        elif cur is not None:
            sections[cur].append(line)
    return {k: "\n".join(v).strip() for k, v in sections.items()}


def _num(s: str) -> float | None:
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def parse_os_release(txt: str) -> dict:
    kv = {}
    for line in txt.splitlines():
        k, _, v = line.partition("=")
        if k:
            kv[k.strip()] = v.strip().strip('"')
    return {"name": kv.get("PRETTY_NAME") or kv.get("NAME"), "id": kv.get("ID"), "version": kv.get("VERSION_ID")}


def parse_meminfo(txt: str) -> dict:
    kv = {}
    for line in txt.splitlines():
        m = re.match(r"(\w+):\s+(\d+)", line)
        if m:
            kv[m.group(1)] = int(m.group(2)) * 1024
    return {
        "total": kv.get("MemTotal"), "available": kv.get("MemAvailable"),
        "swap_total": kv.get("SwapTotal"),
        "swap_used": (kv["SwapTotal"] - kv.get("SwapFree", 0)) if kv.get("SwapTotal") else 0,
    }


def parse_df(txt: str) -> list[dict]:
    out = []
    lines = txt.splitlines()
    typed = bool(lines) and "Type" in lines[0]
    for line in lines[1:]:
        p = line.split()
        if typed and len(p) >= 7:
            dev, fs, size, used, avail, pct, mnt = p[0], p[1], p[2], p[3], p[4], p[5], " ".join(p[6:])
        elif not typed and len(p) >= 6:
            dev, fs, size, used, avail, pct, mnt = p[0], None, p[1], p[2], p[3], p[4], " ".join(p[5:])
        else:
            continue
        if not size.isdigit() or int(size) == 0:
            continue
        out.append({
            "device": dev, "fs": fs, "mount": mnt, "size": int(size) * 1024,
            "used": int(used) * 1024 if used.isdigit() else None,
            "pct": int(pct.rstrip("%")) if pct.rstrip("%").isdigit() else None,
        })
    return out


def parse_netdev(txt: str) -> dict[str, dict]:
    out = {}
    for line in txt.splitlines():
        if ":" not in line or "|" in line:
            continue
        name, _, rest = line.partition(":")
        v = rest.split()
        if len(v) < 16:
            continue
        n = [int(x) for x in v[:16]]
        out[name.strip()] = {
            "rx_bytes": n[0], "rx_packets": n[1], "rx_errs": n[2], "rx_drop": n[3],
            "tx_bytes": n[8], "tx_packets": n[9], "tx_errs": n[10], "tx_drop": n[11], "collisions": n[13],
        }
    return out


def parse_links(txt: str) -> dict[str, dict]:
    out = {}
    for line in txt.splitlines():
        p = line.split()
        if len(p) < 6:
            continue
        name, speed, duplex, state, mtu, kind = p[:6]
        sp = _num(speed)
        out[name] = {
            "speed": int(sp) if sp and sp > 0 else None,
            "duplex": duplex if duplex in ("full", "half") else None,
            "state": state, "mtu": int(mtu) if mtu.isdigit() else None, "kind": kind,
        }
    return out


def parse_wireless(proc: str, iw: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for line in proc.splitlines()[2:]:
        name, _, rest = line.partition(":")
        p = rest.split()
        if len(p) >= 3:
            lvl = _num(p[2].rstrip("."))
            out[name.strip()] = {"signal_dbm": lvl if lvl is not None and lvl < 0 else None}
    cur = None
    for line in iw.splitlines():
        line = line.strip()
        if line.startswith("iface "):
            cur = line.split()[1]
            out.setdefault(cur, {})
        elif cur and line.startswith("signal:"):
            out[cur]["signal_dbm"] = _num(line.split()[1])
        elif cur and line.startswith("tx bitrate:"):
            out[cur]["tx_bitrate"] = _num(line.split()[2])
        elif cur and line.startswith("rx bitrate:"):
            out[cur]["rx_bitrate"] = _num(line.split()[2])
        elif cur and line.startswith("SSID:"):
            out[cur]["ssid"] = line[5:].strip()[:64]
        elif cur and line.startswith("freq:"):
            out[cur]["freq"] = _num(line.split()[1])
        elif cur and line.startswith("Not connected"):
            out[cur]["connected"] = False
    return {k: v for k, v in out.items() if v}


def parse_ipaddr(txt: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in txt.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\S+)", line)
        if m:
            out.setdefault(m.group(1), []).append(m.group(2))
    return out


def parse_default_route(txt: str) -> str | None:
    m = re.search(r"default via (\S+)", txt)
    return m.group(1) if m else None


def parse_neigh(txt: str) -> list[dict]:
    out = []
    for line in txt.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]{17})\s*(\S+)?", line)
        if m:
            out.append({"ip": m.group(1), "dev": m.group(2), "mac": m.group(3), "state": m.group(4)})
            continue
        p = line.split()  # format /proc/net/arp
        if len(p) >= 6 and re.match(r"\d+\.\d+\.\d+\.\d+$", p[0]) and p[3] != "00:00:00:00:00:00" and ":" in p[3]:
            out.append({"ip": p[0], "dev": p[5], "mac": p[3].lower(), "state": None})
    return out


def parse_snmp_tcp(txt: str) -> dict:
    lines = [l for l in txt.splitlines() if l.startswith("Tcp:")]
    if len(lines) < 2:
        return {}
    keys, vals = lines[0].split()[1:], lines[1].split()[1:]
    kv = dict(zip(keys, vals))
    return {k: int(kv[k]) for k in ("OutSegs", "RetransSegs", "InErrs", "InSegs") if k in kv and kv[k].lstrip("-").isdigit()}


def parse_listen(txt: str) -> list[dict]:
    out, seen = [], set()
    for line in txt.splitlines():
        p = line.split()
        if not p:
            continue
        proto = p[0].lower()
        if proto.startswith(("tcp", "udp")) and len(p) >= 5:
            # ss : « tcp LISTEN 0 128 0.0.0.0:22 … » ; netstat : « tcp 0 0 0.0.0.0:22 … »
            local = p[3] if p[1].isdigit() else p[4]
            m = re.search(r":(\d+)$", local)
            if m:
                key = (proto[:3], int(m.group(1)))
                if key not in seen:
                    seen.add(key)
                    out.append({"proto": key[0], "port": key[1], "addr": local.rsplit(":", 1)[0]})
    return sorted(out, key=lambda x: (x["proto"], x["port"]))


def parse_kv(txt: str) -> dict:
    out = {}
    for line in txt.splitlines():
        k, _, v = line.partition("=")
        if k and v.strip():
            out[k.strip()] = v.strip()
    return out


def parse_pressure(txt: str) -> dict:
    out = {}
    for line in txt.splitlines():
        m = re.match(r"(\w+) some avg10=([\d.]+) avg60=([\d.]+) avg300=([\d.]+)", line)
        if m:
            out[m.group(1)] = {"avg10": float(m.group(2)), "avg60": float(m.group(3)), "avg300": float(m.group(4))}
    return out


def parse_inventory(out: str, collected_at: float | None = None) -> dict:
    """Transforme la sortie brute du script en inventaire structuré."""
    s = split_sections(out)
    collected_at = collected_at or time.time()
    uname = s.get("uname", "").split()
    cpu_lines = s.get("cpu", "").splitlines()
    cpu_model = None
    cores = None
    for l in cpu_lines:
        if ":" in l:
            cpu_model = cpu_model or l.split(":", 1)[1].strip()
        elif l.strip().isdigit():
            cores = int(l.strip())
    load = [_num(x) for x in s.get("loadavg", "").split()[:3]]
    up = _num((s.get("uptime", "").split() or [None])[0])
    temps = [t / 1000 for t in (_num(x) for x in s.get("thermal", "").split()) if t and 0 < t < 150000]
    time_kv = parse_kv(s.get("time", ""))
    ntp_line = s.get("time", "").splitlines()[0] if s.get("time") else ""
    remote_epoch = _num(time_kv.get("epoch"))
    links = parse_links(s.get("links", ""))
    counters = parse_netdev(s.get("netdev", ""))
    addrs = parse_ipaddr(s.get("ipaddr", ""))
    wifi = parse_wireless(s.get("wireless", ""), s.get("iw", ""))
    ifaces = []
    for name in sorted(set(links) | set(counters)):
        if name == "lo":
            continue
        ifaces.append({"name": name, **links.get(name, {}), **counters.get(name, {}),
                       "ipv4": addrs.get(name, []), "wifi": wifi.get(name)})
    dmi = parse_kv(s.get("dmi", ""))
    model = s.get("devicetree", "").strip() or None
    sudo_lines = s.get("sudo_dmi", "").splitlines()
    serial = sudo_lines[0].strip() if sudo_lines and ":" not in sudo_lines[0] else None
    return {
        "collected_at": int(collected_at),
        "hostname": s.get("hostname") or (uname[1] if len(uname) > 1 else None),
        "kernel": uname[2] if len(uname) > 2 else None,
        "system": uname[0] if uname else None,
        "arch": uname[3] if len(uname) > 3 else None,
        "os": parse_os_release(s.get("os_release", "")),
        "uptime_s": int(up) if up else None,
        "load": load if all(v is not None for v in load) and load else None,
        "cpu": {"model": cpu_model, "cores": cores},
        "memory": parse_meminfo(s.get("meminfo", "")),
        "disks": parse_df(s.get("df", "")),
        "interfaces": ifaces,
        "default_gateway": parse_default_route(s.get("routes", "")),
        "dns": [l.split()[1] for l in s.get("resolv", "").splitlines() if len(l.split()) > 1],
        "neighbors": parse_neigh(s.get("neigh", "")),
        "tcp": parse_snmp_tcp(s.get("snmp", "")),
        "listening": parse_listen(s.get("listen", "")),
        "hardware": {
            "vendor": dmi.get("sys_vendor") or dmi.get("board_vendor"),
            "model": model or dmi.get("product_name") or dmi.get("board_name"),
            "version": dmi.get("product_version"), "bios": dmi.get("bios_version"), "serial": serial,
            "memory_modules": [l.strip() for l in sudo_lines[1:] if ":" in l][:32],
        },
        "temperature_max": round(max(temps), 1) if temps else None,
        "ntp_synced": {"yes": True, "no": False}.get(ntp_line.strip()),
        "clock_skew_s": round(remote_epoch - collected_at, 1) if remote_epoch else None,
        "virtualization": (s.get("virt") or "").strip() or None,
        "pressure": parse_pressure(s.get("pressure", "")),
        "containers": [
            dict(zip(("name", "image", "status"), l.split("|", 2))) for l in s.get("containers", "").splitlines() if "|" in l
        ],
    }


# ------------------------------------------------------------------ connexion
class SSHResult:
    def __init__(self, ok: bool, kind: str | None = None, error: str | None = None,
                 host_key: str | None = None, host_key_type: str | None = None, fingerprint: str | None = None,
                 inventory: dict | None = None, duration: float | None = None):
        self.ok, self.kind, self.error = ok, kind, error
        self.host_key, self.host_key_type, self.fingerprint = host_key, host_key_type, fingerprint
        self.inventory, self.duration = inventory, duration


def available() -> bool:
    return asyncssh is not None


async def collect(ip: str, port: int, username: str, secret: str, auth_type: str,
                  passphrase: str | None = None, pinned_key: str | None = None, use_sudo: bool = False,
                  connect_timeout: float = 10.0, command_timeout: float = 60.0) -> SSHResult:
    """Se connecte, vérifie la clé d'hôte épinglée, exécute le script et parse l'inventaire.
    kind en cas d'échec : auth | hostkey_changed | unreachable | timeout | error."""
    if asyncssh is None:
        return SSHResult(False, "error", "module asyncssh absent")
    t0 = time.monotonic()
    opts: dict = {
        "username": username, "port": port, "connect_timeout": connect_timeout,
        "login_timeout": connect_timeout, "agent_path": None, "client_keys": None,
        "password": None, "preferred_auth": "publickey,keyboard-interactive,password",
        "keepalive_interval": 0,
    }
    if pinned_key:
        # la clé connue est la seule acceptée : un changement échoue avant toute authentification
        opts["known_hosts"] = ([asyncssh.import_public_key(pinned_key)], [], [])
    else:
        opts["known_hosts"] = None
    if auth_type == "key":
        try:
            opts["client_keys"] = [asyncssh.import_private_key(secret, passphrase)]
        except (asyncssh.KeyImportError, ValueError) as e:
            return SSHResult(False, "error", f"clé privée illisible : {e}")
        opts["preferred_auth"] = "publickey"
    else:
        opts["password"] = secret
        opts["preferred_auth"] = "keyboard-interactive,password"
    try:
        async with asyncssh.connect(ip, **opts) as conn:
            key = conn.get_server_host_key()
            host_key = key.export_public_key().decode().strip() if key else None
            key_type = key.get_algorithm() if key else None
            fp = key.get_fingerprint("sha256") if key else None
            script = SCRIPT + (SUDO_SCRIPT if use_sudo else "\ns end\n")
            res = await asyncio.wait_for(conn.run("sh -s", input=script, check=False), command_timeout)
            out = res.stdout if isinstance(res.stdout, str) else (res.stdout or b"").decode("utf-8", "replace")
            if MARK not in out:
                return SSHResult(False, "error", "shell POSIX indisponible sur cet hôte",
                                 host_key, key_type, fp, duration=time.monotonic() - t0)
            inv = parse_inventory(out)
            return SSHResult(True, None, None, host_key, key_type, fp, inv, round(time.monotonic() - t0, 2))
    except asyncssh.HostKeyNotVerifiable as e:
        return SSHResult(False, "hostkey_changed", f"clé d'hôte différente de celle épinglée : {e}")
    except asyncssh.PermissionDenied:
        return SSHResult(False, "auth", "authentification refusée")
    except (asyncio.TimeoutError, TimeoutError):
        return SSHResult(False, "timeout", "délai dépassé")
    except (OSError, asyncssh.ConnectionLost) as e:
        return SSHResult(False, "unreachable", str(e)[:200])
    except asyncssh.Error as e:
        return SSHResult(False, "error", str(e)[:200])
