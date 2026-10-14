# ATTACKER — Pre-Built Attack Lab

A self-contained attack lab that runs real open-source attack tools against
intentionally vulnerable test environments. The test environment is destroyed
during the attacks. ATTACKER produces the archived logs and ground truth that
**ThreatLoop** reads and defends against.

ATTACKER is a separate, pre-built project. It does not run during the hackathon.
It only **attacks and records** — it never defends, never responds, never runs
an LLM server, and never exposes an HTTP API.

> **Scope:** ATTACKER only ever targets its own disposable, intentionally
> vulnerable lab targets on a private RFC1918 subnet. Real-tool execution refuses
> any non-lab target unless explicitly overridden (`ALLOW_NONLAB=1`).

---

## Two ways to run

**A) Live mode — watch real attacks on a dashboard** (`./run_live.sh`)
Executes the 11 attacks *for real* against a live local OWASP Juice Shop and
shows every step on a browser dashboard: each request firing, which attacks
succeed, the actual stolen credentials (emails + password hashes dumped by SQL
injection), a live damage tally, and the target's health. Every number shown is
measured from real traffic. Use this to *see* what's happening.

**B) Batch mode — generate the dataset** (`./run_all.sh`)
Produces the archived logs + manifest + damage report that ThreatLoop (part 2)
reads. Deterministic, needs no live target. Use this to feed the defense system.

Both write the same four files to `runs/<run_id>/` so either can feed ThreatLoop.

---

## Quick start — live dashboard

Four simple commands (full cheat-sheet in **COMMANDS.md**). They all feed the
same dashboard at `http://localhost:8900`, and every run is saved to disk, so
results survive refresh, restart, and closing a command.

```bash
cd attacker
./start_targets.sh      # 1. start the vulnerable shop (Juice Shop :3000; --dvwa adds DVWA :80)
./baseline.sh           # 2. scan the clean target — the "before" snapshot
./dashboard.sh          # 3. open the console at :8900 (viewer; leave running)
./attack.sh             # 4. run the real attacks (separate terminal) — console updates live
./stop.sh               # stop EVERYTHING (both websites + dashboard) in one command
```

Or all-in-one: `./run_live.sh`. A second vulnerable target, **DVWA**, is
available via `./start_targets.sh --dvwa` (http://localhost:80); point the
attacker at it with `JUICE_URL=http://localhost:80 ./attack.sh`.

On `http://localhost:8900/`:
- **Before / After** strip — the clean baseline (ports open, app healthy, 0 compromises) next to the post-attack state (compromises, records stolen).
- **Attacks** column — all 11, each turning *running* → *success/partial* with a live summary and the damage caused.
- **Live activity** feed — every request/hit/stolen-record as it happens.
- **Stolen credentials** table — the real user emails + password hashes dumped from the live DB by SQL injection.
- **Damage tally** — compromises, records stolen, ports probed, bytes exfiltrated, injections.
- **History** — every past run, click **View** to reopen it; **Clear history** to remove saved live runs.
- **Health light** — the target stays *up* throughout (the app survives; the attacks still succeed and are fully visible).

> Note: Juice Shop is built to withstand these attacks, so the website itself
> won't visibly break. The dashboard is where you see the attacks land.

### Persistence & history (SQLite database)
Every run is recorded in a history database at `state/history.db`, and its full
detail is saved to `runs/<run_id>/` (`events.jsonl`, `meta.json`, `report.md/json`,
plus the ThreatLoop logs). The dashboard reads from disk + DB, so a refresh
still shows the last run's compromises, and a restart still shows the full
history. In the **History** panel each run has:
- **★ save** — pin it so a bulk clear won't delete it,
- **View** — reopen its full results,
- **🗑** — delete just that one run (removes its DB row and its files).

**Clear unsaved** deletes all unsaved live runs at once; ★-saved runs and batch
runs are kept. The baseline snapshot lives in `state/baseline.json`.

### Fits ThreatLoop (part 2) directly
Both modes — live (`./attack.sh`) and batch (`./run_all.sh`) — write the **same
four files** ThreatLoop consumes into `runs/<run_id>/`:

| File            | ThreatLoop component (THREATLOOP-HACKATHON.md) |
|-----------------|------------------------------------------------|
| `auth.log`      | Auth parser → brute-force / spray / impossible-travel rules |
| `network.jsonl` | Network parser → port-scan / exfiltration rules + IsolationForest |
| `proxy.json`    | Proxy parser → SQL-injection + prompt-injection detection |
| `manifest.json` | `eval/score.py` ground truth (recall / FPR / precision) — never read by detection |

So in the hackathon: point ThreatLoop at a run with `./setup.sh --run <run_id>`
and its ingestion, rules, ML, and eval all read this contract unchanged. The two
localhosts stay separate concerns: `:3000` is the attacked target, `:8900` is
ATTACKER's own console — ThreatLoop reads neither service, only the archived
files. The extra live files (`events.jsonl`, `meta.json`, `report.*`) are
ATTACKER-only and ignored by ThreatLoop.

---

## Quick start — batch dataset

```bash
cd attacker

# Produce a full archived run (normalized ground-truth logs; no live targets needed):
./run_all.sh

# Reproducible run (fixed id + fixed base clock):
./run_all.sh --run-id run_20240115_1430 --base 1705329000

# List and validate/stage a run for ThreatLoop to read:
./setup.sh --list
./setup.sh --run run_20240115_1430
```

Each run writes `runs/<run_id>/` with:

| File            | Shape                         | Contents                                   |
|-----------------|-------------------------------|--------------------------------------------|
| `auth.log`      | syslog lines                  | failed/accepted logins, account activity   |
| `network.jsonl` | one JSON object per line      | connections, scans, data transfers         |
| `proxy.json`    | JSON array of request objects | HTTP requests, SQLi payloads, injections   |
| `manifest.json` | JSON ground truth             | which attacks ran, when, expected signals  |

> `manifest.json` is read **only** by ThreatLoop's `eval/` scorer. Detection
> code must never read it.

---

## Two execution modes

ATTACKER always emits the **normalized ground-truth logs** — a stable, parseable,
deterministic dataset in the exact schema ThreatLoop consumes. This is all
ThreatLoop needs as input.

- **`EXEC_REAL_TOOLS=0` (default):** emit the normalized logs only. No live
  targets or tools required. Fully reproducible.
- **`EXEC_REAL_TOOLS=1`:** additionally drive the real tools (Hydra, Nmap,
  sqlmap, Caldera) against live lab targets when installed and reachable. The
  normalized logs are still the authoritative, archived output.

```bash
EXEC_REAL_TOOLS=1 ./run_all.sh          # drive real tools at the lab too
EXEC_REAL_TOOLS=1 ALLOW_NONLAB=1 ...     # override the lab-only safety guard
```

---

## The 11 test cases

| ID    | Technique   | Tool            | Target          | Expected outcome                        |
|-------|-------------|-----------------|-----------------|-----------------------------------------|
| TC-01 | T1110.001   | Hydra           | Linux SSH       | repeated failed logins, compromise      |
| TC-02 | T1110.003   | Hydra           | Linux SSH       | low attempts across many accounts       |
| TC-03 | T1046       | Nmap            | lab host        | many ports from one source              |
| TC-04 | T1190       | sqlmap          | Juice Shop      | SQLi patterns in parameters             |
| TC-05 | T1048       | Caldera         | lab host        | large outbound transfer                 |
| TC-06 | T1078       | Caldera         | Juice Shop      | impossible travel for one account       |
| TC-07 | prompt-inj  | Python script   | prompt handler  | injection payloads, canned responses    |
| TC-08 | T1190       | sqlmap + tamper | Juice Shop      | encoded/obfuscated SQLi                  |
| TC-09 | prompt-inj  | Python script   | prompt handler  | paraphrased injection, same intent      |
| TC-10 | T1046       | Nmap (timing)   | lab host        | slow scan, evades thresholds            |
| TC-11 | T1048       | Caldera (timing)| lab host        | low-and-slow exfil over hours           |

Each test case is a separate file under `attacks/` and can be rerun alone:

```bash
bash attacks/tc03_port_scan.sh runs/<run_id>      # append to an existing run
python3 lib/run.py finalize --run-dir runs/<run_id>
```

Slow cases (TC-10, TC-11) spread their records across hours of **log
timestamps** without taking hours of wall-clock time — detection operates on the
timestamps in the logs, not on real elapsed time.

Benign background traffic is generated into every run (no manifest entry), so
ThreatLoop has a benign baseline to train its IsolationForest on and to measure
a false-positive rate against.

---

## Layout

```
attacker/
├── config.sh                 # lab subnet, target hosts, execution flags
├── setup.sh                  # reset targets / validate+stage a run / list runs
├── run_all.sh                # batch: execute all 11 test cases and archive the run
├── run_live.sh               # live: start target + dashboard, run real attacks
├── live/
│   ├── engine.py             # real attacks against the live target + live report
│   ├── server.py             # stdlib dashboard server (SSE, no deps)
│   └── index.html            # live attack dashboard
├── lib/
│   ├── testcases.json        # catalog: the single source of truth per TC
│   ├── run.py                # run engine: generators, staging, finalize, manifest
│   └── common.sh             # shell helpers + lab-target safety guard
├── targets/
│   ├── juice_shop/launch.sh  # OWASP Juice Shop launcher
│   ├── dvwa/launch.sh        # DVWA launcher
│   ├── ssh_host/setup_accounts.sh  # disposable lab SSH account roster
│   └── prompt_handler.py     # simulated prompt handler (no model, no server)
├── attacks/
│   ├── tc01_ssh_bruteforce.sh ... tc11_slow_exfil.sh
├── recorders/
│   ├── start_recorders.sh    # wire up rsyslog/Zeek/proxy or use engine output
│   └── stop_recorders.sh     # stop collectors; targets left destroyed
└── runs/
    └── <run_id>/             # auth.log, network.jsonl, proxy.json, manifest.json
```

---

## Integration with ThreatLoop

ThreatLoop **never modifies ATTACKER**. It **only reads** from
`attacker/runs/<run_id>/`:

- reads the logs as if from a live protected system under attack,
- reads the manifest **only** in `eval/score.py` (never in detection logic),
- writes its own alerts/triage/actions to its own database.

```bash
# In ThreatLoop:
./setup.sh --run run_20240115_1430   # stages logs from attacker/runs/<run_id>/
```

---

## What ATTACKER does NOT do

- Does not run a local LLM server or load any model.
- Does not expose HTTP APIs.
- Does not recover or clean up the test environment.
- Does not respond to attacks — it only attacks and records.
- Never writes into a run after it is archived (except explicit reruns you invoke).

---

## Deployment checklist

- [ ] Open-source tools installed for live mode (Caldera, sqlmap, Hydra, Nmap, Zeek/Suricata)
- [ ] Lab targets (Juice Shop, DVWA, SSH host) launch cleanly on the lab subnet
- [ ] All eleven attack scripts run individually and as a suite
- [ ] `./run_all.sh` completes end-to-end with all four output files written
- [ ] `./setup.sh --run <run_id>` validates and stages the run for ThreatLoop
