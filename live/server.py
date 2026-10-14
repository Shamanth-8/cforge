#!/usr/bin/env python3
"""Live dashboard server (Python stdlib only), disk-backed.

Serves the dashboard and reflects attack runs that are persisted on disk, so:
  - refreshing the page still shows the last run's compromises,
  - restarting the server still shows the full run history,
  - an attack started by a SEPARATE command (./attack.sh) shows up live here.

The server is a VIEWER of disk state. Attacks write events to
runs/<id>/events.jsonl; the server tails that file for the live feed and reads
meta.json / report.json for history and snapshots.

  python3 live/server.py [--port 8900] [--no-open]
"""
import argparse
import glob
import json
import os
import re
import shutil
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import engine
import db

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS_ROOT = engine.RUNS_ROOT
STATE_DIR = engine.STATE_DIR
_RID_RE = re.compile(r"^[A-Za-z0-9_]+$")

_run_lock = threading.Lock()
_running = {"active": False}


# --------------------------------------------------------------------------- #
# Disk helpers
# --------------------------------------------------------------------------- #
def _read_json(path, default=None):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return default


def _reconcile():
    """Sync the history DB with what's actually on disk (runs added by either
    mode, or removed out-of-band), preserving each run's 'saved' flag."""
    disk_ids = set()
    for d in glob.glob(os.path.join(RUNS_ROOT, "*")):
        if not os.path.isdir(d):
            continue
        rid = os.path.basename(d)
        meta = _read_json(os.path.join(d, "meta.json"))
        if meta is None:
            # Batch run (run_all.sh) — synthesize from report/manifest.
            rep = _read_json(os.path.join(d, "report.json")) or {}
            man = _read_json(os.path.join(d, "manifest.json")) or {}
            if not rep and not man:
                continue
            meta = {"run_id": rid, "mode": "batch",
                    "target": rep.get("target", "batch dataset"),
                    "started": None, "finished": None, "status": "done",
                    "totals": rep.get("totals", {})}
        disk_ids.add(rid)
        db.upsert(meta, mtime=os.path.getmtime(d))
    for rid in db.known_ids() - disk_ids:
        db.delete(rid)


def _list_runs():
    _reconcile()
    return db.list_runs()


def _safe_run_dir(rid):
    if not rid or not _RID_RE.match(rid):
        return None
    d = os.path.join(RUNS_ROOT, rid)
    return d if os.path.isdir(d) else None


def delete_run(rid):
    d = _safe_run_dir(rid)
    if not d:
        db.delete(rid or "")
        return False
    shutil.rmtree(d, ignore_errors=True)
    db.delete(rid)
    return True


def set_saved(rid, saved):
    if rid and _RID_RE.match(rid):
        db.set_saved(rid, saved)
        return True
    return False


def _latest_run_id():
    runs = _list_runs()
    return runs[0]["run_id"] if runs else None


def _events_path(rid):
    return os.path.join(RUNS_ROOT, rid, "events.jsonl")


def _read_events(rid):
    path = _events_path(rid)
    out = []
    if os.path.exists(path):
        with open(path) as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    try:
                        out.append(json.loads(ln))
                    except Exception:  # noqa: BLE001
                        pass
    return out


# --------------------------------------------------------------------------- #
# Run triggers (in-process; attacks may also be started by ./attack.sh)
# --------------------------------------------------------------------------- #
def start_attack():
    with _run_lock:
        if _running["active"]:
            return False
        _running["active"] = True

    def worker():
        try:
            engine.run_live()          # writes events to disk; SSE tails them
        finally:
            _running["active"] = False
    threading.Thread(target=worker, daemon=True).start()
    return True


def start_baseline():
    def worker():
        engine.baseline_scan()
    threading.Thread(target=worker, daemon=True).start()
    return True


def clear_history():
    """Remove unsaved live runs; pinned ('saved') runs and batch runs are kept."""
    _reconcile()
    saved = {r["run_id"] for r in db.list_runs() if r["saved"]}
    removed = 0
    for d in glob.glob(os.path.join(RUNS_ROOT, "live_*")):
        if not os.path.isdir(d):
            continue
        rid = os.path.basename(d)
        if rid in saved:
            continue
        shutil.rmtree(d, ignore_errors=True)
        db.delete(rid)
        removed += 1
    try:
        os.remove(os.path.join(STATE_DIR, "current.json"))
    except OSError:
        pass
    return removed


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002  (quiet)
        pass

    def _send(self, code, body, ctype="application/json"):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)
        if p == "/" or p.startswith("/index"):
            with open(os.path.join(HERE, "index.html"), "rb") as fh:
                self._send(200, fh.read(), "text/html; charset=utf-8")
        elif p == "/events":
            self._stream_events()
        elif p == "/api/runs":
            self._send(200, json.dumps({"runs": _list_runs()}))
        elif p == "/api/latest":
            self._send(200, json.dumps({"run_id": _latest_run_id()}))
        elif p == "/api/run":
            rid = (q.get("id") or [None])[0]
            if not rid or not os.path.isdir(os.path.join(RUNS_ROOT, rid)):
                self._send(404, json.dumps({"error": "not found"}))
                return
            self._send(200, json.dumps({
                "meta": _read_json(os.path.join(RUNS_ROOT, rid, "meta.json")),
                "report": _read_json(os.path.join(RUNS_ROOT, rid, "report.json")),
                "events": _read_events(rid)}))
        elif p == "/api/baseline":
            self._send(200, json.dumps(
                _read_json(os.path.join(STATE_DIR, "baseline.json"), {})))
        elif p == "/state":
            self._send(200, json.dumps({"running": _running["active"],
                                        "current": _latest_run_id()}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/start" or p == "/api/attack":
            self._send(200, json.dumps({"started": start_attack()}))
        elif p == "/api/baseline":
            start_baseline()
            self._send(200, json.dumps({"started": True}))
        elif p == "/api/clear":
            self._send(200, json.dumps({"cleared": clear_history()}))
        elif p == "/api/run/save":
            q = parse_qs(urlparse(self.path).query)
            rid = (q.get("id") or [None])[0]
            saved = (q.get("saved") or ["1"])[0] not in ("0", "false", "")
            self._send(200, json.dumps({"ok": set_saved(rid, saved), "saved": saved}))
        elif p == "/api/run/delete":
            q = parse_qs(urlparse(self.path).query)
            rid = (q.get("id") or [None])[0]
            self._send(200, json.dumps({"deleted": delete_run(rid)}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    # SSE: tail the latest run's events; switch when a newer run appears.
    def _stream_events(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        cur = _latest_run_id()
        pos = 0  # stream a freshly-selected run from its start
        last_keepalive = time.time()
        try:
            while True:
                newest = _latest_run_id()
                if newest != cur:
                    cur = newest
                    pos = 0
                    if cur:
                        self._write({"type": "reload", "run_id": cur})
                if cur:
                    pos = self._tail(cur, pos)
                now = time.time()
                if now - last_keepalive > 12:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    last_keepalive = now
                time.sleep(0.4)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _tail(self, rid, pos):
        path = _events_path(rid)
        if not os.path.exists(path):
            return pos
        size = os.path.getsize(path)
        if size <= pos:
            return pos
        with open(path) as fh:
            fh.seek(pos)
            data = fh.read()
        last_nl = data.rfind("\n")
        if last_nl == -1:
            return pos
        complete = data[:last_nl]
        for ln in complete.split("\n"):
            ln = ln.strip()
            if ln:
                self.wfile.write(("data: %s\n\n" % ln).encode())
        self.wfile.flush()
        return pos + len(complete.encode()) + 1

    def _write(self, obj):
        self.wfile.write(("data: %s\n\n" % json.dumps(obj)).encode())
        self.wfile.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8900)
    ap.add_argument("--no-open", action="store_true")
    args = ap.parse_args()

    os.makedirs(RUNS_ROOT, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)
    db.init(STATE_DIR)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = "http://localhost:%d/" % args.port
    print("[dashboard] %s" % url)
    print("[dashboard] target: %s" % engine.JUICE_URL)
    print("[dashboard] viewer only — run ./attack.sh (or the Launch button) to attack")
    if not args.no_open:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] shutting down")


if __name__ == "__main__":
    main()
