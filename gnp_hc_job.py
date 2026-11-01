#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GNP HC JOB — idempotentno izvršavanje HC komandi (task_id + retry + evidence).

Problem: ista HC komanda se izvršavala više puta (retry, ponovljen zahtjev,
dva agenta) — npr. dvaput otvori program ili dvaput ukuca tekst.

Rješenje: `task_id = sha1(node|op|params)`; ako je isti task već `done`,
vraća keširan rezultat BEZ izvršavanja. Uz svaku akcionu komandu ide dokaz
(screenshot hash prije/poslije) i zapis u gnp_evidence.

CLI:
  python3 gnp_hc_job.py run <node> "<hc komanda>" [--ttl 900] [--retry 2]
  python3 gnp_hc_job.py status <task_id>
  python3 gnp_hc_job.py list [N]
  python3 gnp_hc_job.py gc [dana]

Python:
  from gnp_hc_job import job
  job("linux3", "open xterm")            # izvrši jednom
  job("linux3", "open xterm")            # -> {"cached": True, ...}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
import urllib.request

FLEET = os.environ.get("GNP_FLEET_URL","http://127.0.0.1:7200/fleet")
DB = os.environ.get("GNP_JOBS_DB", os.path.expanduser("~/.gnp/hc_jobs.db"))
TOK_FILES = (os.environ.get("GNP_TOKEN_FILE", os.path.expanduser("~/.gnp/token")),)
MUTATING = ("tap", "type", "key", "run", "open", "uiact", "drag", "scroll", "mouse", "click", "shell")


def _tok() -> str:
    v = os.getenv("GNP_HC_TOKEN")
    if v:
        return v
    for f in TOK_FILES:
        try:
            for ln in open(f, encoding="utf-8", errors="replace"):
                if ln.startswith("GNP_HC_TOKEN="):
                    return ln.split("=", 1)[1].strip().strip('"\'')
        except OSError:
            pass
    return ""


TOK = _tok()


def _db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB, timeout=5)
    c.execute("CREATE TABLE IF NOT EXISTS jobs("
              "task_id TEXT PRIMARY KEY, node TEXT, cmd TEXT, status TEXT, "
              "attempts INT, result TEXT, ev_id TEXT, ts REAL, done_ts REAL)")
    return c


def _hc(node: str, cmd: str, timeout: int = 120) -> dict:
    body = json.dumps({"cmd": cmd, "to": node, "tok": TOK}).encode()
    req = urllib.request.Request(FLEET, data=body, headers={"Content-Type": "application/json"})
    d = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    res = d.get("results") or d.get("rezultati") or {}
    return res.get(node) or d


def task_id(node: str, cmd: str) -> str:
    return hashlib.sha1((node + "|" + cmd.strip()).encode("utf-8", "replace")).hexdigest()[:20]


def job(node: str, cmd: str, ttl: int = 900, retry: int = 2, timeout: int = 120,
        evidence: bool = True) -> dict:
    """Izvrši HC komandu najviše jednom za dati task_id (u TTL prozoru)."""
    tid = task_id(node, cmd)
    now = time.time()
    c = _db()
    row = c.execute("SELECT status,result,ev_id,done_ts FROM jobs WHERE task_id=?", (tid,)).fetchone()
    if row and row[0] == "done" and (now - (row[3] or 0)) < ttl:
        c.close()
        return {"ok": True, "cached": True, "task_id": tid, "evidence_id": row[2],
                "result": json.loads(row[1] or "{}")}
    c.execute("INSERT OR REPLACE INTO jobs VALUES(?,?,?,?,?,?,?,?,?)",
              (tid, node, cmd[:500], "running", 0, "", "", now, None))
    c.commit(); c.close()

    op = cmd.strip().split()[0] if cmd.strip() else ""
    before = after = ""
    if evidence and op in MUTATING:
        try:
            before = (_hc(node, "shot_fast", 60).get("sha") or "")[:16]
        except Exception:
            before = ""

    res, err, attempts = {}, "", 0
    for attempt in range(retry + 1):
        attempts = attempt + 1
        try:
            res = _hc(node, cmd, timeout)
            if res.get("ok"):
                break
            err = str(res.get("err") or res.get("out") or "")[:200]
        except Exception as e:
            err = str(e)[:200]
        if attempt < retry:
            time.sleep(0.8 * (attempt + 1))

    if evidence and op in MUTATING:
        try:
            after = (_hc(node, "shot_fast", 60).get("sha") or "")[:16]
        except Exception:
            after = ""

    ok = bool(res.get("ok"))
    ev_id = ""
    try:
        import importlib, os as _os
        _m = _os.environ.get("GNP_EVIDENCE_MODULE", "gnp_evidence")
        EV = importlib.import_module(_m)
        ev_id = EV.record("hc",
                          {"before_sha": before, "after_sha": after,
                           "changed": bool(before and after and before != after),
                           "cmd": cmd[:120], "attempts": attempts},
                          tool=op or "hc", ok=ok, sid="hc-job")
    except Exception:
        pass

    c = _db()
    c.execute("UPDATE jobs SET status=?, attempts=?, result=?, ev_id=?, done_ts=? WHERE task_id=?",
              ("done" if ok else "failed", attempts, json.dumps(res, ensure_ascii=False)[:8000],
               ev_id, time.time(), tid))
    c.commit(); c.close()
    return {"ok": ok, "cached": False, "task_id": tid, "attempts": attempts,
            "evidence_id": ev_id, "changed": bool(before and after and before != after),
            "err": err, "result": res}


def status(tid: str) -> dict:
    c = _db()
    r = c.execute("SELECT task_id,node,cmd,status,attempts,ev_id,ts,done_ts FROM jobs WHERE task_id=?",
                  (tid,)).fetchone()
    c.close()
    if not r:
        return {"ok": False, "err": "nema task"}
    return {"ok": True, "task_id": r[0], "node": r[1], "cmd": r[2], "status": r[3],
            "attempts": r[4], "evidence_id": r[5], "ts": r[6], "done_ts": r[7]}


def ls(n: int = 10) -> list[dict]:
    c = _db()
    rows = c.execute("SELECT task_id,node,cmd,status,attempts,ts,done_ts FROM jobs "
                     "ORDER BY ts DESC LIMIT ?", (n,)).fetchall()
    c.close()
    return [{"task_id": r[0], "node": r[1], "cmd": r[2][:60], "status": r[3],
             "attempts": r[4], "ts": r[5], "done_ts": r[6]} for r in rows]


def gc(days: int = 7) -> dict:
    cutoff = time.time() - days * 86400
    c = _db()
    n = c.execute("DELETE FROM jobs WHERE COALESCE(done_ts, ts) < ?", (cutoff,)).rowcount
    c.commit(); c.close()
    return {"removed": n, "older_than_days": days}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["run", "status", "list", "gc"])
    ap.add_argument("arg", nargs="?")
    ap.add_argument("arg2", nargs="?")
    ap.add_argument("--ttl", type=int, default=900)
    ap.add_argument("--retry", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.cmd == "run":
        if not a.arg or not a.arg2:
            print(json.dumps({"ok": False, "err": 'treba: run <node> "<komanda>"'})); return 2
        r = job(a.arg, a.arg2, a.ttl, a.retry, a.timeout)
    elif a.cmd == "status":
        r = status(a.arg or "")
    elif a.cmd == "list":
        r = ls(int(a.arg or 10))
    else:
        r = gc(int(a.arg or 7))
    print(json.dumps(r, ensure_ascii=False, indent=1))
    return 0 if (isinstance(r, list) or r.get("ok")) else 1


if __name__ == "__main__":
    sys.exit(main())
