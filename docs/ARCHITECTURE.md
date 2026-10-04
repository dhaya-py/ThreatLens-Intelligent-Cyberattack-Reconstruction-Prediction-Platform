# ThreatLens — Architecture & Design

This document is the design baseline for the ThreatLens prototype. It covers the
final architecture, database schema, repository layout, the synthetic attack
scenario, the correlation and prediction algorithms, and known risks and
simplifications. Later phases implement exactly what is described here; where an
implementation deviates, this file is updated.

---

## 1. Specification analysis

The core product promise is **reconstruction from fragments**: the system receives
heterogeneous telemetry (auth, DNS, process, network), with the malicious events
buried in a much larger benign stream, and must *derive* — not be told — which
events form an attack, how it progressed, where it started, and where it is
likely to go next. Every number on the dashboard must be traceable to stored
events through an explicit, explainable computation.

Key implications:

| Requirement | Design consequence |
|---|---|
| Deterministic, reproducible demo | Seeded generator with fixed base timestamp; analysis pipeline is pure and order-stable (sorts by `(timestamp, id)`); demo reset truncates and restarts identities. |
| No hardcoded metrics / graph | Dashboard reads only API responses; API reads only persisted engine output; engines read only `security_events` + inventory. |
| Explainability everywhere | Every engine output carries `evidence` (event IDs + human-readable reasons) and `confidence`. |
| Must distinguish benign vs malicious | Generator emits benign *look-alikes* (admin PowerShell, IT-admin RDP, normal APP→DB SQL by the same service account, occasional failed logins). |
| No cheating | Generator ground truth is written to a **separate** file (`ground_truth.json`) used only by tests to score the engines. It is never ingested. |
| LLM optional | The investigation assistant consumes a structured evidence bundle; a deterministic template answerer is the default when no API key is set. |

---

## 2. Final architecture

A single FastAPI service (modular monolith) + PostgreSQL + a React SPA. No queue,
no Redis, no microservices — the dataset is small (~5k events) and analysis runs
as a batch pipeline in well under a second.

```
                  ┌────────────────────────────────────────────────────────┐
 scripts/         │ backend (FastAPI)                                       │
 generate_dataset │                                                        │
   │ JSON/CSV     │  api/ ──► services/ ──► engines/ (pure functions)      │
   ▼              │   │          │             ├─ normalization            │
 POST /events/ ───┼──►│          │             ├─ detection (signals)      │
   ingest         │   │          │             ├─ correlation              │
                  │   │          │             ├─ lateral_movement         │
                  │   │          │             ├─ graph                    │
                  │   │          │             ├─ mitre                    │
                  │   │          │             ├─ root_cause               │
                  │   │          │             ├─ risk                     │
                  │   │          │             └─ prediction               │
                  │   │          ▼                                         │
                  │   │    repositories/ (SQLAlchemy) ──► PostgreSQL       │
                  │   │                                                    │
                  │   └── investigation service ──► LLMProvider (optional) │
                  └────────────────────────────────────────────────────────┘
                                  ▲ JSON over /api/v1
                  ┌───────────────┴────────────────┐
                  │ frontend (React + TS + Vite)   │
                  │ nginx serves build, proxies /api│
                  └────────────────────────────────┘
```

**Layering rules**

- `engines/` are pure Python: they take plain dataclasses / ORM-detached
  snapshots and return result dataclasses. No DB access, no I/O. This makes them
  trivially unit-testable and deterministic.
- `services/` orchestrate: load data via `repositories/`, call engines in order,
  persist results in one transaction.
- `api/` is thin: validation (Pydantic schemas) and response shaping only.

**Analysis pipeline** (run by `AnalysisService.rebuild()` after ingestion or via
demo mode):

1. Load inventory + all events, sorted by `(timestamp, id)`.
2. **Detection** — rule detectors attach *signals* to individual events
   (score 0–1, reason, technique hint). Some detectors are windowed
   (brute force, port scan) and stateful against a baseline (first-seen pairs).
3. **Correlation** — link signal events into chains; connected components above
   a threshold become incidents.
4. **Lateral movement** — explicit pattern matcher over the incident's events.
5. **MITRE mapping** — config-driven mapping of signals → attack steps.
6. **Graph** — nodes/edges derived from incident events.
7. **Root cause**, 8. **Risk**, 9. **Prediction**.
10. Persist everything (replacing previous analysis output).

---

## 3. Database schema

All timestamps are `timestamptz` (UTC). JSON columns use `JSONB` on PostgreSQL
(plain `JSON` on SQLite for unit tests). Enumerations are stored as `varchar`
validated at the application layer (avoids painful Postgres enum migrations).

### Inventory

**hosts** — `id`, `hostname` (unique), `ip_address` (unique), `operating_system`,
`department`, `criticality` (int 1–5), `role`, `network_zone`, `created_at`

**users** — `id`, `username` (unique), `display_name`, `department`,
`privilege_level` (`standard | elevated | admin | domain_admin`),
`is_service_account`, `created_at`

### Telemetry

**security_events** — `id`, `external_id` (unique, nullable; ingestion dedup key),
`timestamp`, `event_type` (`authentication | process | dns | network | file`),
`source` (log source, e.g. `windows_security`, `sysmon`, `dns_server`, `firewall`),
`host_id` → hosts, `destination_host_id` → hosts (nullable), `username`,
`source_ip`, `destination_ip`, `process_name`, `parent_process`, `command_line`,
`domain`, `protocol`, `destination_port`, `outcome` (`success | failure`),
`raw_log` (text), `metadata` (json), `ingested_at`

Indexes: `timestamp`, `(host_id, timestamp)`, `username`, `source_ip`, `event_type`.

**network_connections** — `id`, `event_id` → security_events, `timestamp`,
`source_host_id` → hosts, `destination_host_id` → hosts, `source_ip`,
`destination_ip`, `username`, `protocol`, `port`, `bytes_sent`

A denormalised projection of network/auth events where both endpoints are
resolved. Used for connectivity baselines (prediction) and lateral movement.

### Analysis output (rebuilt by the pipeline)

**incidents** — `id`, `reference` (e.g. `INC-1042`), `title`, `severity`, `status`,
`first_seen`, `last_seen`, `root_host_id` → hosts, `risk_score` (0–100),
`confidence`, `summary`, `root_cause` (json: evidence + explanation),
`created_at`, `updated_at`

**incident_events** — (`incident_id`, `event_id`) PK, `role` (`signal | context`),
`correlation_confidence`, `reasons` (json)

**attack_steps** — `id`, `incident_id`, `sequence`, `timestamp`, `host_id`,
`tactic`, `technique_id`, `technique_name`, `confidence`, `description`,
`evidence` (json), `event_ids` (json)

**attack_edges** — `id`, `incident_id`, `source_node`, `source_type`,
`destination_node`, `destination_type`, `relationship`, `timestamp`, `username`,
`protocol`, `port`, `confidence`, `evidence` (json), `event_ids` (json)

Node keys are typed strings: `host:WEB-01`, `user:svc_app`, `ip:203.0.113.66`,
`process:WEB-01:powershell.exe`, `domain:cdn-sync.example`.

**lateral_movements** — `id`, `incident_id`, `source_host_id`,
`destination_host_id`, `username`, `protocol`, `port`, `timestamp`,
`confidence`, `reason`, `evidence` (json), `event_ids` (json)

**host_risk_scores** — `id`, `incident_id`, `host_id`, `score`, `status`
(`initial_entry | compromised | accessed | targeted | observed`), `factors` (json);
unique (`incident_id`, `host_id`)

**target_predictions** — `id`, `incident_id`, `host_id`, `rank`, `score`,
`reasons` (json); unique (`incident_id`, `host_id`)

All analysis tables cascade-delete from `incidents`, so a rebuild is
`DELETE FROM incidents` + insert.

---

## 4. Repository structure

```
backend/
  app/
    api/v1/          routers (events, incidents, hosts, investigate, demo, health)
    core/            config, database session, logging
    models/          SQLAlchemy ORM models
    schemas/         Pydantic request/response models
    repositories/    DB access
    services/        orchestration (ingestion, analysis, investigation, demo)
    engines/         pure detection / correlation / graph / mitre / risk / prediction
    utils/
    main.py
  alembic/           migrations
  tests/
frontend/
  src/ components/ pages/ features/ services/ hooks/ types/ utils/
data/
  raw/               sample input files for manual ingestion
  generated/         generator output (events.json, events.csv, ground_truth.json)
scripts/
  generate_dataset.py
  seed_database.py
docs/
docker-compose.yml
README.md
```

---

## 5. Attack simulation

**Network** (seed `1042`, base date `2026-03-14`, UTC):

| Host | IP | OS | Zone | Dept | Criticality |
|---|---|---|---|---|---|
| WEB-01 | 10.10.1.10 | Windows Server 2019 (IIS) | dmz | Digital | 3 |
| APP-01 | 10.10.2.20 | Windows Server 2022 | app | Engineering | 4 |
| DB-01 | 10.10.3.30 | Windows Server 2022 (SQL Server) | data | Finance | 5 |
| FILE-01 | 10.10.3.40 | Windows Server 2019 | data | Operations | 4 |
| BACKUP-01 | 10.10.3.50 | Ubuntu 22.04 | data | IT | 5 |
| DC-01 | 10.10.0.5 | Windows Server 2022 (AD DS) | infra | IT | 5 |
| WS-FIN-01…, WS-HR-01…, WS-ENG-01…, WS-IT-01 | 10.10.10.x | Windows 11 | corp | various | 2 |

Attacker infrastructure uses documentation ranges (`203.0.113.0/24`) and a
`.example` C2 domain so nothing in the dataset points at real infrastructure.

**Malicious chain** (all on 2026-03-14):

| Time | Host | Observation | Intended technique |
|---|---|---|---|
| 09:52–10:01 | WEB-01 | ~40 failed RDP logons for `webadmin` from 203.0.113.66, then success | T1110.001 Brute Force → T1078 Valid Accounts |
| 10:03 | WEB-01 | `explorer.exe → powershell.exe -nop -w hidden -enc …` | T1059.001 PowerShell |
| 10:03 | WEB-01 | DNS `update.cdn-sync.example` → outbound 443 to 203.0.113.66 | T1071.001 / T1105 |
| 10:05 | WEB-01 | `rundll32.exe comsvcs.dll MiniDump <lsass pid>` | T1003.001 LSASS Memory |
| 10:08 | WEB-01 | `net user /domain`, `net group "Domain Admins" /domain`, `nltest` | T1087.002 Account Discovery |
| 10:09 | WEB-01 | burst of connections to 10.10.2.0/24 & 10.10.3.0/24 on 22/445/1433/3389/5985 | T1046 Network Service Discovery |
| 10:10 | WEB-01→APP-01 | network logon `svc_app` over WinRM (first-ever pair) | T1078 + T1021.006 WinRM |
| 10:11 | APP-01 | `wsmprovhost.exe → powershell.exe` as `svc_app` | T1021.006 remote execution |
| 10:13 | APP-01→DB-01 | `sqlcmd.exe` (parent `powershell.exe`) bulk `SELECT` on customer tables | T1213 Data from Information Repositories |
| 10:16 | APP-01→FILE-01 | SMB `\\FILE-01\ADMIN$` + `PSEXESVC.exe` service execution | T1021.002 SMB/Admin Shares, T1569.002 |
| 10:18 | FILE-01 | read of `\\FILE-01\it$\scripts\backup_config.xml` | T1552.001 Credentials in Files |
| 10:21 | FILE-01→BACKUP-01 | single SSH connection attempt (no auth yet) | T1046 (probe) |

`svc_backup` runs a nightly job **on FILE-01** connecting to BACKUP-01 over SSH,
so its credentials are exposed on FILE-01. Combined with the probe and
BACKUP-01's criticality, BACKUP-01 should rank as the *Likely Next Target* —
derived from data, not asserted.

**Benign activity** (two days: 2026-03-13 baseline + 2026-03-14), roughly 5k events:

- workstation Kerberos logons to DC-01, occasional typo'd failed logons (1–2)
- DNS lookups to common SaaS domains
- WEB-01 → APP-01 HTTP 8080 (normal app tier traffic)
- APP-01 → DB-01 1433 as `svc_app` from `java.exe` (same account as the attacker uses!)
- scheduled tasks (`svchost.exe → taskhostw.exe`, defrag, Windows Update)
- IT admin `it.admin` RDP from WS-IT-01 to APP-01/FILE-01 in the afternoon
- benign signed PowerShell maintenance script on APP-01 (no `-enc`, scheduled)
- nightly FILE-01 → BACKUP-01 SSH as `svc_backup`; file-share access from workstations

The benign look-alikes are deliberate: a detector that fires on "any PowerShell"
or "any RDP" will create false positives that the tests catch.

---

## 6. Correlation algorithm

**Stage 1 — Signals.** Each detector is a small, named, configurable rule:

| Detector | Logic (thresholds configurable) |
|---|---|
| `auth_bruteforce` | ≥10 failed auths for same (target host, source IP) in 10 min |
| `auth_success_after_failures` | success following a brute-force window |
| `external_auth` | successful interactive/remote logon from a non-RFC1918 source |
| `encoded_powershell` | `powershell` with `-enc`/`-EncodedCommand`/`-w hidden`/`IEX` |
| `lsass_access` | command line or target referencing `lsass`, `MiniDump`, `sekurlsa` |
| `recon_commands` | `net user|group /domain`, `nltest`, `whoami /all` bursts |
| `port_scan` | one source → ≥8 distinct (host, port) pairs in 2 min |
| `first_seen_remote_logon` | remote-protocol logon for a (src host, dst host, user) never seen in baseline |
| `remote_exec_parent` | process whose parent is `wsmprovhost.exe`, `PSEXESVC.exe`, `wmiprvse.exe` |
| `service_account_anomaly` | service account running an interactive tool (`sqlcmd`, `powershell`) instead of its baseline process |
| `admin_share_access` | access to `ADMIN$`/`C$`/`IPC$` from a non-admin workstation |
| `credential_file_access` | file read matching `*pass*`, `*cred*`, `*config*.xml`, `unattend.xml` |
| `suspicious_dns` | domain not seen in baseline, queried by a process with a signal |

Event suspicion = `1 − Π(1 − sᵢ)` over its signals (noisy-OR). Events with
suspicion ≥ 0.4 become **signal events**.

**Stage 2 — Pairwise links.** For signal events *a*, *b* with
`0 ≤ t_b − t_a ≤ W` (W = 45 min, sliding window over time-sorted events), compute

```
link(a,b) = decay(Δt) · min(1, Σ wₖ·featureₖ(a,b))
  same_host            0.35   a.host == b.host
  pivot                0.45   b.host == a.destination_host (auth/conn moves to b)
  same_user            0.25   a.username == b.username (non-null, non-system)
  same_source_ip       0.25   a.source_ip == b.source_ip (non-null)
  process_lineage      0.30   b.parent_process == a.process_name on same host
  credential_flow      0.30   a is credential access on H and b uses a credential on/from H
decay(Δt) = exp(−Δt / τ), τ = 30 min
```

Links with `link ≥ 0.35` are kept.

**Stage 3 — Incidents.** Union-find over kept links gives connected components.
A component becomes an incident if it has ≥ 3 signal events spanning ≥ 2 distinct
detector families. Each event's `correlation_confidence` is the maximum link
score attaching it to the component (or its own suspicion for singletons
promoted via context).

**Stage 4 — Context expansion.** Non-signal events directly tied to incident
events (same host & process within 60 s, e.g. the DNS lookup made by the
malicious PowerShell; network projection of a malicious logon) join with role
`context` and confidence `0.5 · parent confidence`.

**Lateral movement** is matched explicitly over incident events:
`auth/connection (src≠dst, internal, protocol ∈ {SMB, RDP, WinRM, SSH, RPC})`
with `src` already compromised earlier in the incident, optionally followed
within 10 min by execution on `dst` under the same user or a remote-exec parent.
Confidence = 0.45 base + 0.25 execution observed + 0.15 source compromised
earlier + 0.15 first-seen pair.

**Root cause** scores each incident host:
earliest signal (rank-based, 0.35) + external source involvement (0.25) +
has outbound lateral movement (0.2) + no inbound lateral movement (0.1) +
mean correlation confidence (0.1). The top host is the root; the explanation is
templated from the contributing evidence.

---

## 7. Risk & prediction

**Host risk** (weights in `app/core/scoring.py`, overridable via env/JSON):

| Factor | Points |
|---|---|
| Asset criticality | `criticality × 5` (max 25) |
| Suspicious events on host | `min(20, 4 × signal_count)` |
| Credential access on host | +15 |
| Lateral movement (in / out) | +15 in, +5 out |
| Unusual authentication | +10 |
| Attack-chain position | `10 × (1 − hops_from_latest / max_hops)` |

Clamped to 0–100; every applied factor is returned as `{name, points, evidence}`.
Incident risk = max host risk + 2 per additional compromised host (cap 100).

**Next-target prediction** ranks every host that is *not* already compromised:

```
score = 0.30·reachability + 0.25·credential_exposure + 0.20·criticality
      + 0.15·recent_probe   + 0.10·chain_proximity           (each in [0,1])
```

- **reachability** — fraction of compromised hosts with baseline connections to
  the candidate, weighted up for admin protocols (SSH/SMB/RDP/WinRM).
- **credential_exposure** — users who logged on to a compromised host in the
  prior 24 h *and* have historically authenticated to the candidate.
- **criticality** — `criticality / 5`.
- **recent_probe** — connection attempts from compromised hosts during the incident.
- **chain_proximity** — inverse hop distance from the most recently compromised host.

Displayed as 0–100 with the top factor contributions as numbered reasons. It is
labelled **"Likely Next Target"** with the explicit caveat that it is a
heuristic ranking, not a forecast.

---

## 8. Risks & simplifications

| Risk / simplification | Mitigation |
|---|---|
| Detectors tuned to one scenario (overfitting) | Generic thresholds, benign look-alikes in data, tests asserting *no* false positives on benign look-alikes, ground-truth precision/recall test. |
| Synthetic data is cleaner than real logs | Normalizer accepts multiple field aliases and both JSON & CSV; raw log retained. |
| Batch re-analysis, not streaming | Fine at prototype scale; pipeline is O(n·k) with a sliding window. |
| MITRE mapping is a prototype | Mapping lives in a config table; UI and API label it "observed-pattern mapping". |
| Prediction is heuristic | Exposed factors and weights; never phrased as certain. |
| LLM hallucination | Evidence-only prompt, deterministic fallback, answers cite event IDs which are validated against the bundle. |
| Python version | Docker image uses 3.12; code is kept compatible with 3.11+. |
| Single tenant, no auth | Out of scope for the hackathon; called out in README limitations. |
