#!/usr/bin/env python3
"""Attack history database (SQLite, stdlib only).

A durable index of every attack run: when it ran, what it did, and whether the
user has marked it 'saved' (pinned) so a bulk clear won't remove it. The run's
full detail still lives in runs/<id>/; this DB is the catalog over them.

Lives at state/history.db. Safe for the threaded dashboard server: one short
connection per call, serialized by a lock for writes.
"""
import json
import os
import sqlite3
import threading
import time

_LOCK = threading.Lock()
_PATH = None


def init(state_dir):
    global _PATH
    os.makedirs(state_dir, exist_ok=True)
    _PATH = os.path.join(state_dir, "history.db")
    con = _conn()
    con.execute("""CREATE TABLE IF NOT EXISTS runs(
        run_id   TEXT PRIMARY KEY,
        mode     TEXT,
        target   TEXT,
        started  TEXT,
        finished TEXT,
        status   TEXT,
        totals   TEXT,
        saved    INTEGER DEFAULT 0,
        mtime    REAL)""")
    con.commit()
    con.close()


def _conn():
    con = sqlite3.connect(_PATH, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def upsert(meta, mtime=None):
    """Insert/refresh a run row, preserving its existing 'saved' flag."""
    with _LOCK:
        con = _conn()
        row = con.execute("SELECT saved FROM runs WHERE run_id=?",
                          (meta["run_id"],)).fetchone()
        saved = row["saved"] if row else 0
        con.execute("""INSERT OR REPLACE INTO runs
            (run_id, mode, target, started, finished, status, totals, saved, mtime)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (meta["run_id"], meta.get("mode"), meta.get("target"),
             meta.get("started"), meta.get("finished"), meta.get("status"),
             json.dumps(meta.get("totals", {})), saved,
             mtime if mtime is not None else time.time()))
        con.commit()
        con.close()


def set_saved(run_id, saved):
    with _LOCK:
        con = _conn()
        con.execute("UPDATE runs SET saved=? WHERE run_id=?",
                   (1 if saved else 0, run_id))
        con.commit()
        con.close()


def delete(run_id):
    with _LOCK:
        con = _conn()
        con.execute("DELETE FROM runs WHERE run_id=?", (run_id,))
        con.commit()
        con.close()


def _row(r):
    return {"run_id": r["run_id"], "mode": r["mode"], "target": r["target"],
            "started": r["started"], "finished": r["finished"],
            "status": r["status"], "totals": json.loads(r["totals"] or "{}"),
            "saved": bool(r["saved"])}


def list_runs():
    con = _conn()
    rows = con.execute("SELECT * FROM runs ORDER BY mtime DESC").fetchall()
    con.close()
    return [_row(r) for r in rows]


def get(run_id):
    con = _conn()
    r = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    con.close()
    return _row(r) if r else None


def known_ids():
    con = _conn()
    rows = con.execute("SELECT run_id FROM runs").fetchall()
    con.close()
    return {r["run_id"] for r in rows}
