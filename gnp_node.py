#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GNP node daemon — GNP/1 MVP (jedan čvor = jedan port = jedan token).

Status: RADNI PoC / MVP.  HTTP + JSON samo.

Šta NIJE u MVP-u (i zašto):
  * WebSocket (stream ekrana, push eventa) — stdlib nema WS server; v2 koristi
    aiohttp/websockets. MVP: /screen vraća putanju ili base64, /events je ring
    buffer preko GET ?since=seq.
  * Pravi ACP (initialize / session/new / session/prompt preko stdio) — ovdje je
    /acp SAMO pojednostavljen JSON-RPC most na harness /chat. Pravi ACP adapter
    pripada u gnp_acp.py (v2, stdio JSON-RPC 2.0).
  * Replay zaštita (nonce/ctr) — TODO(GNP/1.1), vidi _check_nonce(): mjesto gdje
    se uvodi X-Gnp-Nonce + X-Gnp-Ts + HMAC i prozor od 60 s.

Sigurnost MVP:
  * X-Token (HC token) obavezan na SVAKI zahtjev. Loopback bez headera se
    prihvata SAMO ako je GNP_NODE_TRUST_LOOPBACK=1.
  * Nivoi: X-Gnp-Level: view|interact|admin (default view).
      view      : /health /caps /screen /fs(read|list|stat) /mcp(op=list) /audit /events /lease(read? ne)
      interact  : + /exec(bez shell) /fs(write|move) /input /lease /mcp(call) /acp /job
      admin     : + /exec shell=true + docker
  * /input traži lease "input:<node>" (holder + fencing token) PRIJE HC akcije.
  * /fs: realpath + allowlist korijena (/root,/tmp,/opt,/home), If-Match sha256.
  * /exec: bez shell=True (osim admin), timeout, max 256 KB izlaza po streamu.
  * Yama: dijete dobija SANITIZOVAN env (bez tajni iz env-a).

Pokretanje:
  python3 gnp_node.py [--port 7140] [--bind 0.0.0.0]
  # ili: GNP_NODE_PORT=7140 GNP_NODE_BIND=0.0.0.0 python3 gnp_node.py
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import shlex
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    ED_AVAILABLE = True
except Exception:  # pragma: no cover
    Ed25519PublicKey = None
    InvalidSignature = Exception
    ED_AVAILABLE = False

VER = "gnp/1-mvp"
BASE = os.environ.get("GNP_NODE_BASE") or os.path.expanduser("~/.gnp")
DB_PATH = os.path.join(BASE, "node_leases.db")
AUDIT_PATH = os.path.join(BASE, "node_audit.jsonl")
AGENTS_PATH = os.path.join(BASE, "node_agents.json")
FS_ROOTS = ("/root", "/tmp", "/opt", "/home")
# Tajne koje se NIKAD ne smiju čitati/pisati kroz /fs ni kroz /exec argumente.
SECRET_DENY = (
    "api_keys.env", "bus.env", ".env", ".ssh",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".pem", ".key", ".p12", ".pfx",
    ".git-credentials", ".netrc", "kubeconfig", "auth.json", "_sessions.json",
    ".thunder", "cli_config.json", "node-daemon.env", "agent-harness.env",
    "node_audit", "node_leases", "/vault", "secret",
)
# Interact smije samo ove programe; sve ostalo (bash/python/sudo/docker/find/xargs)
# traži admin — inače je "interact" = root.
INTERACT_EXEC_ALLOW = {
    "echo", "printf", "ls", "cat", "head", "tail", "wc", "grep", "date", "hostname",
    "whoami", "id", "uname", "pwd", "stat", "file", "du", "df", "free", "ps", "ss",
    "uptime", "sleep", "true", "false", "env", "printenv", "which", "basename",
    "dirname", "realpath", "cut", "sort", "uniq", "tr", "nl", "od", "md5sum",
    "sha256sum", "git",
}
# Audit/lease fajlovi se ne smiju mijenjati kroz /fs write.
FS_WRITE_DENY = ("node_audit", "node_leases", "/etc/", "/proc/", "/sys/")
HC_ADDR = (os.environ.get("GNP_HC_HOST","127.0.0.1"), int(os.environ.get("GNP_HC_PORT","7100")))
HARNESS = os.environ.get("GNP_HARNESS_URL","http://127.0.0.1:7125")
JOBS = os.environ.get("GNP_JOBS_URL","http://127.0.0.1:7135")
MAX_BODY = 2 * 1024 * 1024          # HTTP body
MAX_STREAM = 256 * 1024             # stdout/stderr po streamu
MAX_READ = 8 * 1024 * 1024          # /fs read
MAX_WRITE = 16 * 1024 * 1024        # /fs write
LEVELS = {"view": 0, "interact": 1, "admin": 2}
ENV_FILES = ("/etc/gnp-node.env", "/etc/agent-harness.env")
SANITIZED_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "HOME": "/root",
}
START = time.time()
NODE = os.environ.get("GNP_NODE_NAME") or socket.gethostname()


# ---------------------------------------------------------------- token/env
def _env_file(path: str, key: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                if ln.startswith(key + "="):
                    return ln.split("=", 1)[1].strip().strip("\"'")
    except OSError:
        pass
    return ""


def load_hc_token() -> str:
    v = os.environ.get("GNP_HC_TOKEN", "").strip()
    if v:
        return v
    for p in ENV_FILES:
        v = _env_file(p, "GNP_HC_TOKEN")
        if v:
            return v
    return ""


def load_harness_token() -> str:
    v = os.environ.get("GNP_TOKEN", "").strip()
    if v:
        return v
    return _env_file(os.environ.get("GNP_TOKEN_FILE", os.path.expanduser("~/.gnp/token")), "GNP_TOKEN") or load_hc_token()


TOKEN = load_hc_token()
HARNESS_TOKEN = load_harness_token()
TRUST_LOOPBACK = os.environ.get("GNP_NODE_TRUST_LOOPBACK", "0") == "1"


# ---------------------------------------------------------------- errors/util
class NodeError(Exception):
    def __init__(self, code: int, err: str, **extra):
        super().__init__(err)
        self.code = code
        self.err = err
        self.extra = extra

    def body(self) -> dict:
        d = {"ok": False, "err": self.err}
        d.update(self.extra)
        return d


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def _trim(b: bytes, limit: int = MAX_STREAM):
    if len(b) > limit:
        return b[:limit], True
    return b, False


def _port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


# ---------------------------------------------------------------- audit chain
_audit_lock = threading.Lock()
_audit_state = {"seq": 0, "last": "genesis", "loaded": False}


def audit_init() -> None:
    with _audit_lock:
        if _audit_state["loaded"]:
            return
        seq, last = 0, "genesis"
        seen, bad = set(), False
        try:
            with open(AUDIT_PATH, encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        e = json.loads(ln)
                    except Exception:
                        bad = True
                        continue
                    s = int(e.get("seq", 0))
                    if s in seen:
                        bad = True
                    seen.add(s)
                    if e.get("prev_hash") not in (None, "genesis") and e.get("prev_hash") != last:
                        bad = True
                    seq = s if s else seq
                    last = e.get("hash", last)
        except OSError:
            pass
        if bad:
            try:
                os.replace(AUDIT_PATH, AUDIT_PATH + ".broken_" + time.strftime("%Y%m%d_%H%M%S"))
            except OSError:
                pass
            seq, last = 0, "genesis"
        _audit_state.update(seq=seq, last=last, loaded=True)


def audit_append(agent: str, op: str, target: str, args, result, rc: int) -> dict:
    audit_init()
    args_hash = _sha(_canon(args))[:32]
    result_hash = _sha(_canon(result)[:4096])[:32]
    with _audit_lock:
        seq = _audit_state["seq"] + 1
        prev = _audit_state["last"]
        core = {
            "seq": seq,
            "ts": round(time.time(), 3),
            "agent": agent,
            "op": op,
            "target": target,
            "args_hash": args_hash,
            "result_hash": result_hash,
            "rc": rc,
            "prev_hash": prev,
        }
        core["hash"] = _sha(_canon(core))
        try:
            with open(AUDIT_PATH, "a", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                try:
                    fh.write(json.dumps(core, ensure_ascii=False) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                finally:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        _audit_state.update(seq=seq, last=core["hash"])
        return core


def audit_read(limit: int = 50) -> dict:
    entries = []
    try:
        with open(AUDIT_PATH, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    try:
                        entries.append(json.loads(ln))
                    except Exception:
                        pass
    except OSError:
        pass
    valid, prev, broken = True, "genesis", None
    for e in entries:
        core = {k: e.get(k) for k in ("seq", "ts", "agent", "op", "target",
                                      "args_hash", "result_hash", "rc", "prev_hash")}
        if e.get("prev_hash") != prev or _sha(_canon(core)) != e.get("hash"):
            valid, broken = False, e.get("seq")
            break
        prev = e.get("hash")
    n = max(1, min(int(limit or 50), 1000))
    return {"ok": True, "chain_valid": valid, "broken_at": broken,
            "total": len(entries), "entries": entries[-n:]}


# ---------------------------------------------------------------- events ring
_events = deque(maxlen=1000)
_events_lock = threading.Lock()
_events_seq = 0


def event_add(kind: str, **kw) -> None:
    global _events_seq
    with _events_lock:
        _events_seq += 1
        ev = {"seq": _events_seq, "ts": round(time.time(), 3), "kind": kind}
        ev.update(kw)
        _events.append(ev)


def events_since(since: int, limit: int = 1000) -> dict:
    with _events_lock:
        evs = [e for e in _events if e["seq"] > since][:limit]
        return {"ok": True, "events": evs, "last_seq": _events_seq}


# ---------------------------------------------------------------- leases
_db_lock = threading.Lock()
_db_ready = False


def _db() -> sqlite3.Connection:
    global _db_ready
    cn = sqlite3.connect(DB_PATH, timeout=10)
    cn.execute("PRAGMA busy_timeout=5000")
    if not _db_ready:
        cn.execute("PRAGMA journal_mode=WAL")
        cn.execute("""CREATE TABLE IF NOT EXISTS leases(
            resource TEXT PRIMARY KEY,
            holder TEXT NOT NULL,
            token TEXT NOT NULL,
            ttl REAL NOT NULL,
            expires_at REAL NOT NULL,
            acquired_at REAL NOT NULL,
            renewed_at REAL NOT NULL)""")
        cn.commit()
        _db_ready = True
    return cn


def lease_acquire(resource: str, holder: str, ttl: float) -> dict:
    now = time.time()
    with _db_lock, _db() as cn:
        cn.execute("BEGIN IMMEDIATE")
        row = cn.execute("SELECT holder,token,ttl,expires_at FROM leases WHERE resource=?",
                         (resource,)).fetchone()
        if row and row[3] > now:
            if row[0] != holder:
                raise NodeError(409, "lease zauzet", resource=resource, holder=row[0],
                                ttl_remaining=round(row[3] - now, 1))
            # Isti holder NE dobija ponovo fencing token (anti-token-leak).
            raise NodeError(409, "lease već držiš", resource=resource, holder=holder,
                            ttl_remaining=round(row[3] - now, 1), hint="koristi lease.renew")
        tok = hashlib.sha256(os.urandom(24)).hexdigest()[:16]
        exp = now + ttl
        cn.execute("""INSERT INTO leases(resource,holder,token,ttl,expires_at,acquired_at,renewed_at)
                      VALUES(?,?,?,?,?,?,?)
                      ON CONFLICT(resource) DO UPDATE SET
                        holder=excluded.holder, token=excluded.token, ttl=excluded.ttl,
                        expires_at=excluded.expires_at, acquired_at=excluded.acquired_at,
                        renewed_at=excluded.renewed_at""",
                   (resource, holder, tok, ttl, exp, now, now))
        cn.commit()
        return {"ok": True, "resource": resource, "holder": holder,
                "fencing_token": tok, "renewed": False,
                "expires_at": round(exp, 3), "ttl": ttl}


def lease_renew(resource: str, holder: str, token: str, ttl: float) -> dict:
    now = time.time()
    with _db_lock, _db() as cn:
        cn.execute("BEGIN IMMEDIATE")
        row = cn.execute("SELECT holder,token,expires_at FROM leases WHERE resource=?",
                         (resource,)).fetchone()
        if not row:
            raise NodeError(404, "lease ne postoji", resource=resource)
        if row[0] != holder or not hmac.compare_digest(str(row[1]), str(token)):
            raise NodeError(409, "lease token/holder ne odgovara", resource=resource, holder=row[0])
        if row[2] <= now:
            raise NodeError(409, "lease istekao", resource=resource, holder=row[0])
        exp = now + ttl
        cn.execute("UPDATE leases SET ttl=?,expires_at=?,renewed_at=? WHERE resource=?",
                   (ttl, exp, now, resource))
        cn.commit()
        return {"ok": True, "resource": resource, "holder": holder, "fencing_token": token,
                "expires_at": round(exp, 3), "ttl": ttl}


def lease_release(resource: str, holder: str, token: str) -> dict:
    with _db_lock, _db() as cn:
        cn.execute("BEGIN IMMEDIATE")
        row = cn.execute("SELECT holder,token FROM leases WHERE resource=?",
                         (resource,)).fetchone()
        if not row:
            cn.commit()
            return {"ok": True, "resource": resource, "released": False, "note": "nije postojao"}
        if row[0] != holder or not hmac.compare_digest(str(row[1]), str(token)):
            raise NodeError(409, "lease token/holder ne odgovara", resource=resource, holder=row[0])
        cn.execute("DELETE FROM leases WHERE resource=?", (resource,))
        cn.commit()
        return {"ok": True, "resource": resource, "released": True}


def lease_check(resource: str, holder: str, token: str) -> dict:
    now = time.time()
    with _db_lock, _db() as cn:
        row = cn.execute("SELECT holder,token,expires_at FROM leases WHERE resource=?",
                         (resource,)).fetchone()
    if not row:
        raise NodeError(409, "nema lease za %s" % resource, resource=resource, need="lease")
    if row[0] != holder or not hmac.compare_digest(str(row[1]), str(token)):
        raise NodeError(409, "lease token/holder ne odgovara", resource=resource, holder=row[0])
    if row[2] <= now:
        raise NodeError(409, "lease istekao", resource=resource, holder=row[0])
    return {"holder": row[0], "expires_at": round(row[2], 3)}


def lease_count() -> int:
    try:
        with _db_lock, _db() as cn:
            return int(cn.execute("SELECT COUNT(*) FROM leases WHERE expires_at>?",
                                  (time.time(),)).fetchone()[0])
    except Exception:
        return 0


# ---------------------------------------------------------------- agent policy
_agents_lock = threading.Lock()
_agents_cache = {"mtime": 0.0, "data": None}


def agents_init() -> None:
    """Kreiraj agents.json (600) ako ne postoji: legacy=interact, admin ako je env."""
    if os.path.exists(AGENTS_PATH):
        return
    d = {"agents": {"legacy": {"token_sha256": _sha(TOKEN.encode("utf-8")), "level": "interact",
                               "allow": ["*"]}}}
    adm = os.environ.get("GNP_NODE_ADMIN_TOKEN") or ""
    if adm:
        d["agents"]["admin"] = {"token_sha256": _sha(adm.encode("utf-8")), "level": "admin",
                                "allow": ["*"]}
    try:
        with open(AGENTS_PATH, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2)
        os.chmod(AGENTS_PATH, 0o600)
    except OSError:
        pass


def agents_get(aid: str):
    try:
        st = os.stat(AGENTS_PATH)
    except OSError:
        return None
    with _agents_lock:
        if _agents_cache["data"] is None or st.st_mtime != _agents_cache["mtime"]:
            try:
                with open(AGENTS_PATH, encoding="utf-8") as fh:
                    _agents_cache["data"] = json.load(fh)
            except Exception:
                return None
            _agents_cache["mtime"] = st.st_mtime
        return (_agents_cache["data"].get("agents") or {}).get(aid)


# ---------------------------------------------------------------- path safety
def _is_secret(rp: str) -> bool:
    low = rp.lower().replace("\\", "/")
    return any(d in low for d in SECRET_DENY)


def safe_path(p: str) -> str:
    if not isinstance(p, str) or not p.strip():
        raise NodeError(400, "path obavezan")
    rp = os.path.realpath(p)
    if _is_secret(rp):
        raise NodeError(403, "pristup tajni blokiran", path=rp)
    for root in FS_ROOTS:
        if rp == root or rp.startswith(root + os.sep):
            return rp
    raise NodeError(403, "path van allowlist (%s)" % ",".join(FS_ROOTS), path=p)


# ---------------------------------------------------------------- hc proxy
def hc_call(cmd: str, timeout: float = 25.0) -> dict:
    try:
        s = socket.create_connection(HC_ADDR, timeout=timeout)
    except OSError as e:
        raise NodeError(503, "HC %s:%s nedostupan (%s)" % (HC_ADDR[0], HC_ADDR[1], e))
    try:
        s.settimeout(timeout)
        msg = {"cmd": cmd}
        if TOKEN:
            msg["tok"] = TOKEN
        s.sendall((json.dumps(msg, ensure_ascii=False) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            if len(buf) > 32 * 1024 * 1024:
                raise NodeError(502, "HC odgovor prevelik")
    except socket.timeout:
        raise NodeError(504, "HC timeout (%ss)" % timeout)
    finally:
        s.close()
    try:
        return json.loads(buf.decode("utf-8", "replace").splitlines()[0])
    except Exception:
        raise NodeError(502, "HC nevalidan JSON", raw=buf[:200].decode("utf-8", "replace"))


# ---------------------------------------------------------------- http proxy
def http_json(method: str, url: str, body=None, token: str = "", timeout: float = 60.0):
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json",
        "X-Token": token,
        "X-Gnp-Agent": "gnp-node",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            code = r.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        code = e.code
    except Exception as e:
        raise NodeError(502, "proxy %s ne radi (%s)" % (url, e))
    try:
        return code, json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return code, {"ok": False, "err": "nevalidan JSON od %s" % url,
                      "raw": raw[:500].decode("utf-8", "replace")}


# ---------------------------------------------------------------- capabilities
def caps_detail() -> dict:
    hc = _port_open(*HC_ADDR)
    ev = {
        "hc_7100": hc,
        "harness_7125": _port_open("127.0.0.1", 7125),
        "fleet_7200": _port_open("127.0.0.1", 7200),
        "brain_8065": _port_open("127.0.0.1", 8065),
        "jobs_7135": _port_open("127.0.0.1", 7135),
        "docker_sock": os.path.exists("/var/run/docker.sock"),
        "chromium_bin": any(os.path.exists(p) for p in (
            "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome")),
        "ssh_bin": os.path.exists("/usr/bin/ssh"),
        "fs_roots": {r: os.path.isdir(r) for r in FS_ROOTS},
    }
    caps = {
        "hc": bool(hc),
        "ssh": ev["ssh_bin"],
        "fs": all(ev["fs_roots"].values()),
        "mcp": ev["harness_7125"],
        "acp": ev["harness_7125"],
        "job": ev["jobs_7135"],
        "screen": bool(hc),
        "input": bool(hc),
        "docker": ev["docker_sock"],
        "browser": ev["chromium_bin"],
        "ui": bool(hc),
        "sig": ED_AVAILABLE,
        "exec": True,
        "lease": True,
        "audit": True,
        "events": True,
        "ws": False,
    }
    return {"ok": True, "ver": VER, "node": NODE, "host": socket.gethostname(),
            "caps": caps, "evidence": ev}


# ---------------------------------------------------------------- routes
def _pick_token(body: dict, keys) -> str:
    for k in keys:
        v = body.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def do_exec(body: dict, level: int) -> dict:
    argv = body.get("argv")
    command = body.get("command") or body.get("cmd")
    shell = bool(body.get("shell"))
    if shell and level < LEVELS["admin"]:
        raise NodeError(403, "shell=true traži admin", need="admin")
    if argv is not None:
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise NodeError(400, "argv mora biti neprazna lista stringova")
        base = os.path.basename(argv[0])
    else:
        if not isinstance(command, str) or not command.strip():
            raise NodeError(400, "argv ili command obavezan")
        try:
            parts = shlex.split(command)
        except ValueError as e:
            raise NodeError(400, "nevalidan command (%s)" % e)
        if not parts:
            raise NodeError(400, "prazan command")
        base = os.path.basename(parts[0])
    if base in ("docker", "podman", "docker-compose") and level < LEVELS["admin"]:
        raise NodeError(403, "docker traži admin", need="admin")
    if shell:
        args = [shlex.join(argv) if argv is not None else command]
    else:
        args = list(argv) if argv is not None else parts

    if level < LEVELS["admin"]:
        if base not in INTERACT_EXEC_ALLOW:
            raise NodeError(403, "interact: program nije u allowlisti", program=base,
                            need="admin")
        for a in args[1:]:
            if isinstance(a, str) and a.startswith("/"):
                rp = os.path.realpath(a)
                if _is_secret(rp):
                    raise NodeError(403, "argument pokazuje na tajnu", path=a)

    cwd = body.get("cwd") or BASE
    cwd = safe_path(cwd)
    if not os.path.isdir(cwd):
        raise NodeError(400, "cwd nije direktorij", cwd=cwd)
    try:
        timeout = float(body.get("timeout", 30))
    except Exception:
        raise NodeError(400, "timeout mora biti broj")
    timeout = max(1.0, min(timeout, 300.0))

    t0 = time.time()
    try:
        p = subprocess.Popen(args, cwd=cwd, shell=shell, env=dict(SANITIZED_ENV),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    except FileNotFoundError:
        raise NodeError(400, "program nije nađen", argv=args[:1])
    except Exception as e:
        raise NodeError(400, "exec neuspješan (%s)" % e)
    timed_out = False
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except Exception:
            p.kill()
        out, err = p.communicate()
    ms = round((time.time() - t0) * 1000, 1)
    o, ot = _trim(out or b"")
    e, et = _trim(err or b"")
    return {"ok": True, "rc": p.returncode, "ms": ms, "timed_out": timed_out,
            "stdout": o.decode("utf-8", "replace"), "stderr": e.decode("utf-8", "replace"),
            "stdout_truncated": ot, "stderr_truncated": et,
            "argv": args if not shell else ["<shell>", args[0][:200]]}


def do_fs(body: dict, level: int) -> dict:
    op = str(body.get("op") or "").lower()
    if op in ("write", "move") and level < LEVELS["interact"]:
        raise NodeError(403, "fs %s traži interact" % op, need="interact")
    if op == "list":
        p = safe_path(body.get("path"))
        if not os.path.isdir(p):
            raise NodeError(400, "nije direktorij", path=p)
        items = []
        with os.scandir(p) as it:
            for ent in it:
                if len(items) >= 2000:
                    break
                try:
                    st = ent.stat(follow_symlinks=False)
                    items.append({"name": ent.name,
                                  "type": "dir" if ent.is_dir(follow_symlinks=False) else "file",
                                  "size": st.st_size, "mtime": round(st.st_mtime, 3)})
                except OSError:
                    continue
        items.sort(key=lambda x: (x["type"] != "dir", x["name"]))
        return {"ok": True, "op": "list", "path": p, "count": len(items), "entries": items}

    p = safe_path(body.get("path"))
    if op == "read":
        if not os.path.isfile(p):
            raise NodeError(404, "fajl ne postoji", path=p)
        size = os.path.getsize(p)
        if size > MAX_READ:
            raise NodeError(413, "fajl prevelik za read (>8MB)", size=size)
        with open(p, "rb") as fh:
            data = fh.read()
        sha = _sha(data)
        try:
            return {"ok": True, "op": "read", "path": p, "size": len(data),
                    "sha256": sha, "encoding": "utf-8",
                    "content": data.decode("utf-8")}
        except UnicodeDecodeError:
            import base64
            return {"ok": True, "op": "read", "path": p, "size": len(data),
                    "sha256": sha, "encoding": "base64",
                    "content": base64.b64encode(data).decode()}

    if op == "write":
        content = body.get("content")
        if content is None and body.get("content_b64") is not None:
            import base64
            try:
                content = base64.b64decode(body["content_b64"])
            except Exception:
                raise NodeError(400, "content_b64 nevalidan")
        if not isinstance(content, (str, bytes)):
            raise NodeError(400, "content obavezan")
        data = content.encode() if isinstance(content, str) else content
        if len(data) > MAX_WRITE:
            raise NodeError(413, "content prevelik (>16MB)", size=len(data))
        if_match = body.get("if_match")
        if if_match is not None:
            if not os.path.isfile(p):
                raise NodeError(409, "if_match: fajl ne postoji", path=p)
            cur = _sha(open(p, "rb").read())
            if not hmac.compare_digest(str(if_match), cur):
                raise NodeError(409, "if_match mismatch", path=p, current_sha256=cur)
        d = os.path.dirname(p)
        if not os.path.isdir(d):
            raise NodeError(400, "roditeljski direktorij ne postoji", dir=d)
        tmp = os.path.join(d, ".gnp_tmp_%d_%s" % (os.getpid(), os.path.basename(p)))
        try:
            with open(tmp, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, p)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        return {"ok": True, "op": "write", "path": p, "size": len(data), "sha256": _sha(data)}

    if op == "stat":
        if not os.path.exists(p):
            return {"ok": True, "op": "stat", "path": p, "exists": False}
        st = os.stat(p)
        out = {"ok": True, "op": "stat", "path": p, "exists": True,
               "isdir": os.path.isdir(p), "size": st.st_size,
               "mtime": round(st.st_mtime, 3), "mode": oct(st.st_mode & 0o777)}
        if os.path.isfile(p) and st.st_size <= 32 * 1024 * 1024:
            out["sha256"] = _sha(open(p, "rb").read())
        return out

    if op == "move":
        dst = body.get("dst") or body.get("dest") or body.get("to")
        if not isinstance(dst, str) or not dst.strip():
            raise NodeError(400, "dst obavezan")
        src, dp = safe_path(body.get("path")), safe_path(dst)
        if not os.path.exists(src):
            raise NodeError(404, "izvor ne postoji", path=src)
        if os.path.isdir(dp):
            raise NodeError(400, "dst je direktorij (daj punu putanju)")
        os.replace(src, dp)
        return {"ok": True, "op": "move", "src": src, "dst": dp}

    raise NodeError(400, "nepoznat op (list|read|write|stat|move)")


def _img_b64(r: dict) -> str:
    """HC vrati img_b64 (stariji) ili jpg_b64 (shot_fast/shot_region na Linuxu)."""
    return r.get("img_b64") or r.get("jpg_b64") or r.get("png_b64") or ""


def do_screen(body: dict) -> dict:
    op = str(body.get("op") or "shot").lower()
    want_b64 = bool(body.get("b64"))
    if op == "shot":
        r = hc_call("screenshot")
        if not r.get("ok"):
            return {"ok": False, "op": "shot", "hc": r}
        path = r.get("file")
        out = {"ok": True, "op": "shot", "path": path, "bytes": int(str(r.get("size") or 0)),
               "hc_via": "screenshot"}
        if want_b64 and path and os.path.isfile(path):
            import base64
            raw = open(path, "rb").read()
            out["img_b64"] = base64.b64encode(raw).decode()
            out["bytes"] = len(raw)
            out["mime"] = "image/png"
        return out
    if op == "shot_fast":
        r = hc_call("shot_fast", timeout=30)
        if not r.get("ok"):
            return {"ok": False, "op": "shot_fast", "hc": r}
        import base64
        raw = base64.b64decode(_img_b64(r))
        d = "/tmp/gnp_node_shots"
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "shot_fast_%d.jpg" % int(time.time() * 1000))
        with open(path, "wb") as fh:
            fh.write(raw)
        out = {"ok": True, "op": "shot_fast", "path": path, "bytes": len(raw),
               "w": r.get("w"), "h": r.get("h"), "mime": "image/jpeg"}
        if want_b64:
            out["img_b64"] = _img_b64(r)
        return out
    if op == "region":
        try:
            x, y, w, h = (int(body.get(k)) for k in ("x", "y", "w", "h"))
        except Exception:
            raise NodeError(400, "region traži x,y,w,h")
        r = hc_call("shot_region %d %d %d %d" % (x, y, w, h), timeout=30)
        if not r.get("ok"):
            return {"ok": False, "op": "region", "hc": r}
        import base64
        raw = base64.b64decode(_img_b64(r))
        d = "/tmp/gnp_node_shots"
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "region_%d.jpg" % int(time.time() * 1000))
        with open(path, "wb") as fh:
            fh.write(raw)
        return {"ok": True, "op": "region", "path": path, "bytes": len(raw),
                "region": [x, y, w, h], "mime": "image/jpeg"}
    raise NodeError(400, "nepoznat screen op (shot|shot_fast|region)")


def do_input(body: dict, level: int) -> dict:
    if level < LEVELS["interact"]:
        raise NodeError(403, "input traži interact", need="interact")
    resource = "input:%s" % NODE
    holder = str(body.get("holder") or "").strip()
    ltok = _pick_token(body, ("lease_token", "fencing_token"))
    if not holder or not ltok:
        raise NodeError(409, "input traži lease (holder + lease_token)", resource=resource,
                        hint="POST /lease {op:acquire,resource:'%s'}" % resource)
    lease_check(resource, holder, ltok)

    op = str(body.get("op") or "").lower()
    if op == "tap":
        try:
            x, y = int(body["x"]), int(body["y"])
        except Exception:
            raise NodeError(400, "tap traži x,y")
        cmd = "tap %d %d" % (x, y)
    elif op == "type":
        txt = body.get("text")
        if not isinstance(txt, str) or not txt:
            raise NodeError(400, "type traži text")
        if len(txt) > 4000:
            raise NodeError(413, "text > 4000 znakova")
        cmd = "type " + txt
    elif op == "key":
        key = str(body.get("key") or "").strip()
        if not key:
            raise NodeError(400, "key traži key")
        cmd = "key " + key
    elif op == "scroll":
        try:
            n = int(body.get("amount") or body.get("n") or 3)
        except Exception:
            raise NodeError(400, "scroll traži broj")
        cmd = "scroll %d" % n
    elif op == "drag":
        try:
            x1, y1, x2, y2 = (int(body[k]) for k in ("x1", "y1", "x2", "y2"))
        except Exception:
            raise NodeError(400, "drag traži x1,y1,x2,y2")
        cmd = "drag %d,%d %d,%d" % (x1, y1, x2, y2)
    else:
        raise NodeError(400, "nepoznat input op (tap|type|key|scroll|drag)")
    r = hc_call(cmd, timeout=20)
    return {"ok": bool(r.get("ok")), "op": op, "hc_cmd": cmd.split(" ", 1)[0],
            "lease": {"resource": resource, "holder": holder}, "hc": r}


def do_lease(body: dict) -> dict:
    op = str(body.get("op") or "").lower()
    resource = str(body.get("resource") or "").strip()
    if not resource:
        raise NodeError(400, "resource obavezan")
    if len(resource) > 200:
        raise NodeError(400, "resource predug")
    holder = str(body.get("holder") or "").strip()
    try:
        ttl = float(body.get("ttl") or 60)
    except Exception:
        raise NodeError(400, "ttl mora biti broj")
    ttl = max(5.0, min(ttl, 3600.0))
    if op == "acquire":
        if not holder:
            raise NodeError(400, "holder obavezan za acquire")
        return lease_acquire(resource, holder, ttl)
    if op in ("renew", "release"):
        tok = _pick_token(body, ("token", "fencing_token", "lease_token"))
        if not holder or not tok:
            raise NodeError(400, "holder i token obavezni za %s" % op)
        return lease_renew(resource, holder, tok, ttl) if op == "renew" \
            else lease_release(resource, holder, tok)
    raise NodeError(400, "nepoznat lease op (acquire|renew|release)")


def do_mcp(body: dict, level: int) -> dict:
    op = str(body.get("op") or "list").lower()
    if op == "list":
        code, r = http_json("GET", HARNESS + "/mcp/tools", None, HARNESS_TOKEN, timeout=30)
        if code != 200:
            raise NodeError(502, "harness /mcp/tools vratio %s" % code, harness=r)
        return {"ok": True, "op": "list", "count": r.get("count"), "tools": r}
    if op == "call":
        if level < LEVELS["interact"]:
            raise NodeError(403, "mcp call traži interact", need="interact")
        name = str(body.get("name") or "").strip()
        if not name:
            raise NodeError(400, "name obavezan")
        args = body.get("args") or body.get("arguments") or {}
        try:
            timeout = float(body.get("timeout") or 120)
        except Exception:
            timeout = 120.0
        timeout = max(5.0, min(timeout, 600.0))
        code, r = http_json("POST", HARNESS + "/mcp/call",
                            {"name": name, "args": args}, HARNESS_TOKEN, timeout=timeout)
        if code != 200:
            raise NodeError(502 if code >= 500 else code,
                            "harness /mcp/call vratio %s" % code, harness=r)
        return {"ok": True, "op": "call", "name": name, "result": r}
    raise NodeError(400, "nepoznat mcp op (list|call)")


def do_acp(body: dict, level: int) -> dict:
    """Pojednostavljen JSON-RPC most na harness /chat.

    Pravi ACP (stdio, initialize/session/new/session/prompt) -> gnp_acp.py (v2).
    """
    if level < LEVELS["interact"]:
        raise NodeError(403, "acp traži interact", need="interact")
    rid = body.get("id")
    params = body.get("params") or {}
    text = params.get("text") or params.get("prompt") or params.get("goal") or body.get("text")
    if not isinstance(text, str) or not text.strip():
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32602, "message": "params.text|prompt|goal obavezan"}}
    payload = {"text": text.strip()}
    if params.get("sid"):
        payload["sid"] = params["sid"]
    code, r = http_json("POST", HARNESS + "/chat", payload, HARNESS_TOKEN, timeout=300)
    if code != 200:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32000, "message": "harness /chat vratio %s" % code,
                          "data": r}}
    txt = r.get("text") or r.get("answer") or r.get("message") or ""
    return {"jsonrpc": "2.0", "id": rid, "result": {"text": txt, "harness": r}}


def do_job(body: dict, level: int) -> dict:
    if level < LEVELS["interact"]:
        raise NodeError(403, "job traži interact", need="interact")
    goal = str(body.get("goal") or body.get("text") or "").strip()
    if not goal:
        raise NodeError(400, "goal obavezan")
    payload = {"text": goal}
    if body.get("type"):
        payload["type"] = body["type"]
    try:
        code, r = http_json("POST", JOBS + "/jobs", payload, "", timeout=20)
    except NodeError as e:
        raise NodeError(503, "jobs :7135 nedostupan", detail=e.err)
    if code not in (200, 202):
        raise NodeError(502, "jobs vratio %s" % code, jobs=r)
    return {"ok": True, "job_id": r.get("job_id"), "state": r.get("state"), "jobs": r}


_nonce_lock = threading.Lock()
_nonce_seen: dict = {}


def _check_nonce(hdrs, method: str = "POST") -> bool:
    """Replay zaštita (GNP/1.1).

    POST zahtjevi MORAJU nositi X-Gnp-Ts (unix) i X-Gnp-Nonce (>=16 znakova).
    Odbija se: |now-ts| > 120 s, ponovljen nonce, nevalidan ts.
    GET (read-only) je izuzet.
    """
    if method != "POST":
        return True
    ts = (hdrs.get("X-Gnp-Ts") or "").strip()
    nonce = (hdrs.get("X-Gnp-Nonce") or "").strip()
    if not ts or len(nonce) < 16 or len(nonce) > 128:
        return False
    try:
        t = float(ts)
    except ValueError:
        return False
    now = time.time()
    if abs(now - t) > 120:
        return False
    with _nonce_lock:
        prev = _nonce_seen.get(nonce)
        if prev is not None and now - prev <= 120:
            return False
        _nonce_seen[nonce] = now
        if len(_nonce_seen) > 50000:
            for k, v in list(_nonce_seen.items()):
                if now - v > 120:
                    _nonce_seen.pop(k, None)
    return True


def do_ui(body: dict, level: int) -> dict:
    """a11y sloj: tree (view) i act (interact + lease input:<node>)."""
    op = str(body.get("op") or "tree").lower()
    if op == "tree":
        r = hc_call("uiatree", timeout=20)
        if not r.get("ok"):
            r = hc_call("windows", timeout=10)
        return {"ok": bool(r.get("ok")), "op": "tree", "result": r}
    if op == "act":
        if level < LEVELS["interact"]:
            raise NodeError(403, "ui act traži interact", need="interact")
        name = str(body.get("name") or body.get("ref") or "").strip()
        if not name:
            raise NodeError(400, "ui act traži name/ref")
        holder = str(body.get("holder") or "").strip()
        ltok = _pick_token(body, ("lease_token", "fencing_token"))
        lease_check("input:%s" % NODE, holder, ltok)
        r = hc_call("uiact " + name, timeout=20)
        return {"ok": bool(r.get("ok")), "op": "act", "name": name, "result": r}
    raise NodeError(400, "ui op mora biti tree|act", op=op)


def _qint(vals, default: int) -> int:
    try:
        return int((vals or [str(default)])[0])
    except (TypeError, ValueError):
        raise NodeError(400, "nevalidan broj u query-ju")


# ---------------------------------------------------------------- HTTP server
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "gnp-node/" + VER

    def log_message(self, fmt, *args):
        print("%s %s" % (time.strftime("%H:%M:%S"), fmt % args), flush=True)

    # -- helpers
    def _client_loopback(self) -> bool:
        return (self.client_address or ("",))[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def _send(self, code: int, obj) -> None:
        b = json.dumps(obj, ensure_ascii=False, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Gnp-Node", NODE)
        self.end_headers()
        try:
            self.wfile.write(b)
        except BrokenPipeError:
            pass

    def _read_body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0:
            self.close_connection = True
            raise NodeError(400, "los Content-Length")
        if n > MAX_BODY:
            self.close_connection = True
            raise NodeError(413, "body > 2MB")
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return {}
        try:
            d = json.loads(raw.decode("utf-8"))
        except Exception:
            raise NodeError(400, "nevalidan JSON")
        if not isinstance(d, dict):
            raise NodeError(400, "JSON mora biti objekat")
        return d

    def _auth(self):
        """Vrati (agent, level_str, level_int, via).

        Nivo iz agents.json je GORNJA granica; X-Gnp-Level može samo sniziti.
        """
        aid = (self.headers.get("X-Gnp-Agent") or "legacy")[:64]
        hdr = (self.headers.get("X-Gnp-Level") or "").strip().lower()
        if hdr and hdr not in LEVELS:
            raise NodeError(400, "X-Gnp-Level mora biti view|interact|admin")
        tok = (self.headers.get("X-Token") or "").strip()
        pol = agents_get(aid)
        if pol is None:
            if os.path.exists(AGENTS_PATH) and \
                    os.environ.get("GNP_NODE_STRICT_AGENTS", "1") == "1":
                raise NodeError(401, "nepoznat agent", agent=aid)
            if tok and TOKEN and hmac.compare_digest(tok, TOKEN):
                base_s = "interact"
            elif TRUST_LOOPBACK and self._client_loopback() and not tok:
                base_s = "interact"
            else:
                raise NodeError(401, "X-Token obavezan/neispravan")
            via = "legacy"
        else:
            if not tok or not hmac.compare_digest(_sha(tok.encode("utf-8")), str(pol.get("token_sha256", ""))):
                raise NodeError(401, "agent token ne odgovara", agent=aid)
            base_s = str(pol.get("level") or "view").lower()
            if base_s not in LEVELS:
                raise NodeError(403, "nevalidan policy level", agent=aid)
            via = "policy"
        lvl_s = hdr if hdr in LEVELS else base_s
        if LEVELS[lvl_s] > LEVELS[base_s]:
            lvl_s = base_s
        return aid, lvl_s, LEVELS[lvl_s], via

    def _check_sig(self, agent: str, method: str, path: str, body: dict) -> None:
        """Ed25519 potpis po komandi za agente sa require_sig=true."""
        pol = agents_get(agent) or {}
        if not pol.get("require_sig"):
            return
        if not ED_AVAILABLE:
            raise NodeError(503, "Ed25519 nedostupan na serveru")
        sig = (self.headers.get("X-Gnp-Sig") or "").strip()
        ts = (self.headers.get("X-Gnp-Ts") or "").strip()
        nonce = (self.headers.get("X-Gnp-Nonce") or "").strip()
        if not sig or not ts or not nonce:
            raise NodeError(401, "agent traži potpis (X-Gnp-Sig/Ts/Nonce)")
        try:
            pub = base64.b64decode(str(pol.get("pubkey") or ""))
            raw = base64.b64decode(sig)
        except Exception:
            raise NodeError(401, "nevalidan potpis/pubkey")
        msg = ("GNP1\n%s\n%s\n%s\n%s\n%s\n%s\n" % (
            method, path, agent, ts, nonce,
            _sha(_canon(body)))).encode()
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(raw, msg)
        except InvalidSignature:
            raise NodeError(401, "potpis ne odgovara")
        except Exception as e:
            raise NodeError(401, "potpis greška: %s" % str(e)[:80])

    def _need(self, lvl: int, need: str) -> None:
        if lvl < LEVELS[need]:
            raise NodeError(403, "nivo %s traži %s" % (
                {0: "view", 1: "interact", 2: "admin"}[lvl], need), need=need)

    # -- dispatch
    def do_GET(self):
        self._run("GET")

    def do_POST(self):
        self._run("POST")

    def _run(self, method: str) -> None:
        t0 = time.time()
        path, _, qs = self.path.partition("?")
        query = urllib.parse.parse_qs(qs)
        body, code, resp = {}, 200, None
        agent, lvl_s = "anonymous", "view"
        try:
            body = self._read_body() if method == "POST" else {}
            agent, lvl_s, lvl, via = self._auth()
            self._check_sig(agent, method, path, body)
            if not _check_nonce(self.headers, method):
                raise NodeError(409, "replay (X-Gnp-Ts/X-Gnp-Nonce)")

            if path == "/auth":
                resp = {"ok": True, "agent": agent, "level": lvl_s, "via": via}
            elif path == "/health":
                resp = {"ok": True, "ver": VER, "host": socket.gethostname(), "node": NODE,
                        "caps": ["exec", "fs", "screen", "input", "lease", "mcp", "acp",
                                 "job", "audit", "events"],
                        "lease_count": lease_count(),
                        "uptime": round(time.time() - START, 1)}
            elif path == "/caps":
                resp = caps_detail()
            elif path == "/audit":
                resp = audit_read(_qint(query.get("limit"), 50))
            elif path == "/events":
                resp = events_since(_qint(query.get("since"), 0))
            elif path == "/exec" and method == "POST":
                self._need(lvl, "interact")
                resp = do_exec(body, lvl)
            elif path == "/fs" and method == "POST":
                resp = do_fs(body, lvl)
            elif path == "/screen" and method == "POST":
                self._need(lvl, "view")
                resp = do_screen(body)
            elif path == "/input" and method == "POST":
                resp = do_input(body, lvl)
            elif path == "/ui" and method == "POST":
                resp = do_ui(body, lvl)
            elif path == "/lease" and method == "POST":
                self._need(lvl, "interact")
                resp = do_lease(body)
            elif path == "/mcp" and method == "POST":
                resp = do_mcp(body, lvl)
            elif path == "/acp" and method == "POST":
                resp = do_acp(body, lvl)
            elif path == "/job" and method == "POST":
                resp = do_job(body, lvl)
            else:
                raise NodeError(404, "nepoznata ruta", path=path, method=method)
        except NodeError as e:
            code, resp = e.code, e.body()
        except Exception as e:
            code, resp = 500, {"ok": False, "err": "internal: %s" % str(e)[:200]}
        ms = round((time.time() - t0) * 1000, 1)
        if isinstance(resp, dict):
            resp.setdefault("ms", ms)
            resp.setdefault("agent", agent)
            resp.setdefault("level", lvl_s)
        self._send(code, resp)
        event_add("http", op="%s %s" % (method, path), code=code, agent=agent, ms=ms)
        if path not in ("/health", "/caps", "/events", "/audit"):
            op = "%s %s" % (method, path)
            target = str(body.get("path") or body.get("resource") or body.get("name")
                         or body.get("op") or "")
            audit_append(agent, op, target[:200], body, resp, code)
        print(json.dumps({"t": round(time.time(), 3), "op": "%s %s" % (method, path),
                          "code": code, "ms": ms, "agent": agent, "level": lvl_s},
                         ensure_ascii=False), flush=True)


class Srv(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="GNP NODE DAEMON (GNP/1 MVP)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("GNP_NODE_PORT", "7140")))
    ap.add_argument("--bind", default=os.environ.get("GNP_NODE_BIND", "0.0.0.0"))
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--tls-cert", default=os.environ.get("GNP_NODE_TLS_CERT", "~/.gnp/pki/node.pem"))
    ap.add_argument("--tls-key", default=os.environ.get("GNP_NODE_TLS_KEY", "~/.gnp/pki/node.key"))
    ap.add_argument("--tls-ca", default=os.environ.get("GNP_NODE_TLS_CA", "~/.gnp/pki/ca.pem"))
    a = ap.parse_args()
    if not TOKEN:
        print("UPOZORENJE: HC token nije nađen (GNP_HC_TOKEN / /etc/gnp-node.env) — "
              "samo loopback trust ako je uključen.", flush=True)
    audit_init()
    agents_init()
    try:
        _db()
    except Exception as e:
        print("lease DB init fail: %s" % e, flush=True)
    srv = None
    last = None
    for cand in (a.port, a.port + 1, a.port + 2):
        try:
            srv = Srv((a.bind, cand), Handler)
            break
        except OSError as e:
            last = e
            print("port %d zauzet (%s), probam %d" % (cand, e, cand + 1), flush=True)
    if srv is None:
        print("FAIL: nijedan port nije slobodan (%s)" % last, flush=True)
        return 1
    if a.tls:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.tls_cert, a.tls_key)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(a.tls_ca)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("GNP NODE listening on %s:%d ver=%s node=%s trust_loopback=%s tls=%s"
          % (a.bind, srv.server_address[1], VER, NODE, TRUST_LOOPBACK, a.tls), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
