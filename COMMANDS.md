# ATTACKER — Command Cheat Sheet

All commands run from the `attacker/` folder. They all feed the **same**
dashboard at `http://localhost:8900`, and every run is saved to disk, so results
survive refresh, server restart, and closing a command.

## The simple flow (4 commands)

```bash
# 1. Start the vulnerable shop(s) — the live target that gets attacked
./start_targets.sh            # OWASP Juice Shop on http://localhost:3000
./start_targets.sh --dvwa     # also start DVWA on http://localhost:80

# 2. Scan the target BEFORE attacking — records the clean "before" snapshot
./baseline.sh

# 3. Open the dashboard (viewer only — does NOT attack). Leave it running.
./dashboard.sh                # http://localhost:8900
./dashboard.sh --port 8910    # different port

# 4. Run the real attacks (separate terminal). The open dashboard updates live.
./attack.sh
```

You can close `./attack.sh` after it finishes — refresh the dashboard and the
compromises are still there (saved on disk). Run `./attack.sh` again any time;
each run is added to the **History** panel.

```bash
# Stop EVERYTHING (both websites + the dashboard) in one command:
./stop.sh
```

## The target websites (what gets attacked)

Juice Shop is the main one. DVWA is an optional second vulnerable site.

```bash
./start_targets.sh            # Juice Shop  -> http://localhost:3000
./start_targets.sh --dvwa     # Juice Shop + DVWA -> http://localhost:80
#   DVWA login: admin / password  (set DTS security to "low")
```

To attack DVWA instead of Juice Shop, point the attacker at it:
```bash
JUICE_URL=http://localhost:80 ./baseline.sh
JUICE_URL=http://localhost:80 ./attack.sh
```

## All-in-one (optional)

```bash
./run_live.sh                 # start target + baseline + dashboard + attack, one command
./run_live.sh --no-target     # Juice Shop already running
```

## Batch mode (for ThreatLoop, no live target needed)

```bash
./run_all.sh                  # deterministic logs + manifest + report in runs/<id>/
./setup.sh --list             # list archived runs
./setup.sh --run <run_id>     # validate + stage a run for ThreatLoop
```

## In the dashboard (http://localhost:8900)

- **Scan baseline** — take the clean "before" snapshot from the browser.
- **Launch attacks** — run the attacks from the browser (same as `./attack.sh`).
- **History** — every past run (indexed in a SQLite database, `state/history.db`). Per run:
  - **★ save** — pin the run so a bulk clear won't delete it.
  - **View** — reopen that run's full results.
  - **🗑** — delete just that one run.
- **Clear unsaved** — delete all unsaved live runs at once (★-saved runs and batch runs are kept).

## What's running where

| Thing            | URL / port                | Started by           |
|------------------|---------------------------|----------------------|
| Juice Shop (target) | http://localhost:3000  | `./start_targets.sh` |
| DVWA (optional target) | http://localhost:80 | `./start_targets.sh --dvwa` |
| Dashboard        | http://localhost:8900     | `./dashboard.sh`     |
| **Stop all of the above** | —            | `./stop.sh`          |

## The 11 attacks (7 techniques)

brute force · password spray · port scan · SQL injection (classic + encoded) ·
data exfiltration (bulk + low-and-slow) · impossible travel · prompt injection
(direct + paraphrased).
