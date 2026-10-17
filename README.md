# ATTACKER: Attack Lab

ATTACKER is a self-contained lab that runs 11 attack scenarios against intentionally vulnerable test environments. It records the logs and writes a ground-truth manifest for each run. The test environments are destroyed during the attacks; the archived logs are the output.

ATTACKER only attacks and records. It does not defend, respond, run an LLM server, or expose an HTTP API.

**ThreatLoop** is the defense layer that reads ATTACKER's archived logs. It is not included in this repository. The integration points are described in section 4.

> **Scope:** ATTACKER only targets its own disposable lab environments on the private subnet `192.168.56.0/24`. Real-tool execution refuses non-lab targets unless `ALLOW_NONLAB=1` is set.

---

## 1. Components

**Attack tools**

| Tool | Used for |
|------|----------|
| MITRE Caldera + Atomic Red Team | Adversary emulation, data exfiltration, impossible-travel activity |
| sqlmap | SQL injection, including encoded variants |
| Hydra | SSH brute force and password spraying |
| Nmap | Port scanning, including slow and timing-evasive scans |
| Python scripts | Prompt-injection scenarios against a simulated prompt handler |

**Test targets** (destroyed during a run)

| Target | Role |
|--------|------|
| OWASP Juice Shop (`:3000`) | Vulnerable web app and REST API |
| DVWA (`:80`, optional) | SQL injection and authentication target |
| Linux SSH host | Authentication target |
| Simulated prompt handler | Plain Python function that returns canned responses. It is not a served LLM. |

**Log recorders** (what survives)

| Recorder | Output |
|----------|--------|
| rsyslog or Filebeat | `auth.log` |
| Zeek or Suricata | `network.jsonl` |
| Reverse proxy | `proxy.json` |

### Test cases

| ID | Technique | Tool | Target | Expected signal |
|----|-----------|------|--------|-----------------|
| TC-01 | T1110.001 SSH brute force | Hydra | SSH host | Repeated failed logins from one source |
| TC-02 | T1110.003 Password spraying | Hydra | SSH host | Few attempts per account across many accounts |
| TC-03 | T1046 Port scan | Nmap | Lab host | Many ports probed from one source |
| TC-04 | T1190 SQL injection | sqlmap | Juice Shop | Injection patterns in request parameters |
| TC-05 | T1048 Data exfiltration | Caldera | Lab host | Large outbound transfer |
| TC-06 | T1078 Impossible travel | Caldera | Juice Shop | One account active from distant locations in impossible time |
| TC-07 | Prompt injection | Python | Prompt handler | Injection payloads |
| TC-08 | Encoded SQL injection | sqlmap + tamper | Juice Shop | Obfuscated SQL patterns |
| TC-09 | Paraphrased prompt injection | Python | Prompt handler | Rephrased injection with the same intent |
| TC-10 | Slow port scan | Nmap (timing) | Lab host | Few ports per window, below typical thresholds |
| TC-11 | Low-and-slow exfiltration | Caldera (timing) | Lab host | Transfer spread over a long period |

Each test case is a separate script under `attacks/` and can be rerun on its own. Slow cases spread their records across hours of log timestamps, not wall-clock time. Benign background traffic from three non-attacking sources is written into every run, with no manifest entry.

---

## 2. Quick start

**Requirements:** Bash, Python 3, curl, and Docker for the live targets. Hydra, Nmap, sqlmap, and Caldera are needed only when real-tool execution is enabled.

### A. Live dashboard (real attacks, shown in a browser)

```bash
cd attacker
./start_targets.sh      # start Juice Shop on :3000 (add --dvwa for DVWA on :80)
./baseline.sh           # scan the clean target as the "before" snapshot
./dashboard.sh          # open the console at http://localhost:8900 (leave running)
./attack.sh             # run the 11 attacks in a separate terminal
./stop.sh               # stop the targets and the dashboard
```

Or run everything at once with `./run_live.sh`. To aim the attacks at DVWA instead, use `JUICE_URL=http://localhost:80 ./attack.sh`.

The dashboard shows the before/after state, each attack's result, a live activity feed, the stolen-credential table, and a damage tally. Every live run is saved under `runs/` and recorded in `state/history.db`, so results survive a refresh or restart.

### B. Batch dataset (deterministic, no live target needed)

```bash
cd attacker
./run_all.sh                                                 # new run, normalized logs
./run_all.sh --run-id run_20240115_1430 --base 1705329000    # reproducible run
./setup.sh --list                                            # list archived runs
./setup.sh --run run_20240115_1430                           # validate a run and print its path
```

`setup.sh --run` checks that all four output files exist and are non-empty, and that the JSON parses. It prints the run path and copies nothing.

### Ending a session

```bash
cd attacker && ./stop.sh
```

This stops the targets and the dashboard. Saved runs remain in `runs/` and `state/history.db`.

---

## 3. Output contract

Both modes write the same four files to `runs/<run_id>/`:

| File | Format | Contents |
|------|--------|----------|
| `auth.log` | syslog lines | Login attempts, failures, lockouts, account activity |
| `network.jsonl` | one JSON object per line | Connections, scans, data transfers |
| `proxy.json` | JSON array | HTTP requests, injection payloads, response codes |
| `manifest.json` | JSON | Ground truth: test case IDs, times, source IPs, expected signals |

Live runs also write `events.jsonl`, `meta.json`, and `report.*`. These are used only by the ATTACKER console.

Each run records its status in `meta.json`. Only runs with status `done` are valid input for a defense layer.

### Execution modes

- `EXEC_REAL_TOOLS=0` (default): writes the normalized logs only. Fully reproducible, no live tools needed.
- `EXEC_REAL_TOOLS=1`: also drives the real tools against the lab targets when they are installed and reachable.

### Repository layout

```
attacker/
├── config.sh, setup.sh, run_all.sh, run_live.sh
├── start_targets.sh, baseline.sh, attack.sh, dashboard.sh, stop.sh
├── attacks/                   # tc01 ... tc11
├── targets/                   # Juice Shop, DVWA, SSH host, prompt handler
├── recorders/                 # log collection
├── lib/                       # run engine, test-case catalog
├── live/                      # live dashboard
├── runs/                      # archived runs (generated, not committed)
└── state/                     # dashboard state and history (generated, not committed)
```

---

## 4. Integration with ThreatLoop

ThreatLoop reads ATTACKER's output and never modifies ATTACKER. It treats the archived logs as if they came from a live system under attack.

```
attacker/runs/<run_id>/               (read-only input)
 ├─ auth.log ─────────┐
 ├─ network.jsonl ────┼─► Ingestion ─► Detection ─► Triage ─► Response ─► Protected service
 ├─ proxy.json ───────┘   (events)    (alerts)     (LLM,      (scoped,     (health-checked)
 └─ manifest.json ───────────────────────────────►  advisory)
                                                   Evaluation (joins alerts to manifest)
```

The manifest is read only by the evaluation step. Detection code never reads it.

### Attachment points

| # | Point | Location | Responsibility |
|---|-------|----------|----------------|
| 1 | Ingestion | `ingest/` | Parse `auth.log`, `network.jsonl`, `proxy.json` into events |
| 2 | Detection rules | `rules/` | Flag events as alerts: brute force, password spray, port scan, SQL injection |
| 3 | Anomaly model | `models/` | Model trained on benign events (no manifest entry) |
| 4 | Response layer | `response_layer.py` | Apply allowed, scoped, reversible actions to the protected service; health-check; revert on failure |
| 5 | Triage | `triage/` | LLM proposes one allowed action with a short justification; template fallback when the model is unavailable |
| 6 | Dashboard and feedback | `app.py`, `frontend/` | Alert queue, alert detail, live updates, analyst feedback on missed attacks |
| 7 | Evaluation | `eval/score.py` | Report recall, false-positive rate, precision, and availability per test case |

### Response actions

| Action | Scope | Reversal | Default limit |
|--------|-------|----------|---------------|
| Rate-limit source | One source IP | Automatic removal | 1 hour |
| Temporary IP block | One source IP | Automatic expiry | 4 hours |
| Temporary account lock | One account | Automatic unlock | 30 minutes |
| Host isolation | One host | Automatic release | 2 hours |

Every action has a scope, an expiry, and an undo path. Nothing deletes data, stops a service, or destroys an environment.

### Configuration

```python
ATTACKER_RUN_DIR  = "attacker/runs/<run_id>/"   # read-only input
ALERTS_DB         = "threatloop.db"             # ThreatLoop output
PROTECTED_SERVICE = "http://localhost:8000"     # service being defended
```

`PROTECTED_SERVICE` is a separate system from ATTACKER's test targets. ThreatLoop reads only the archived files, not the live ATTACKER services or the dashboard.
