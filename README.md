# ThreatLens

**Intelligent cyberattack reconstruction & prediction platform.** ThreatLens turns
fragmented security telemetry (authentication, DNS, process, network, file and
database logs) into a reconstructed attack story: a correlated incident, an
interactive attack graph, a MITRE ATT&CK timeline, explicit lateral-movement
detection, root-cause identification, transparent risk scoring, an explainable
"likely next target", and an evidence-grounded AI investigation assistant.

Every number on the dashboard is computed by the backend from the dataset — nothing
is hardcoded — and the whole pipeline is deterministic, so the demo is identical
every run.

> Status: complete end-to-end prototype (Phases 1–12). **122 backend tests** pass on
> Python 3.12 and 3.14; the stack runs under Docker Compose.

---

## Problem

Real intrusions leave evidence scattered across many log sources, buried in a sea
of benign activity. Analysts must manually stitch those fragments into a timeline,
work out where the attacker got in, judge what's at risk, and guess where they'll
go next. It's slow, inconsistent, and hard to explain.

## Solution

ThreatLens ingests heterogeneous telemetry, normalizes it, and runs a deterministic
analysis pipeline that *derives* — not assumes — the attack: which events correlate,
how the attacker moved, where they started, what's at risk, and the likely next
target. Every output carries its evidence and a confidence score, so an analyst can
trust and explain it. An optional LLM assistant phrases answers over that evidence;
a deterministic responder covers the case where no LLM is configured.

## Architecture

A modular monolith — one FastAPI service, PostgreSQL, and a React SPA. No queues,
no microservices; the dataset is small and analysis runs as a sub-second batch.

```
Synthetic Telemetry Generator
        │  (6 native log formats, JSON/CSV)
        ▼
Ingestion ──► Normalization ──► PostgreSQL
                                   │
                                   ▼
                        Analysis pipeline (pure engines)
   detection → correlation → lateral movement → graph
            → MITRE mapping → root cause → risk → prediction
                                   │
                                   ▼
                      Persisted Incident + analysis output
                                   │
                    FastAPI  /api/v1/...   ◄── LLM-optional investigation assistant
                                   │
                                   ▼
                      React SOC dashboard (Vite + Tailwind)
```

**Engines are pure functions** over `EventView` snapshots — no DB, no I/O — which
makes them deterministic and directly testable against ground truth. Services
orchestrate (load → run engines → persist in one transaction); the API is thin.

## Tech stack

- **Backend:** Python 3.12+, FastAPI, SQLAlchemy 2, Alembic, Pydantic v2, PostgreSQL 16
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, React Flow (`@xyflow/react`) + dagre
- **Infra:** Docker, Docker Compose
- **LLM (optional):** Anthropic via an abstraction layer, with a deterministic fallback

## Data flow

1. `generate_dataset.py` writes deterministic telemetry (seed 1042) to
   `data/generated/` as `events.json`, `events.csv`, and `ground_truth.json`.
   The ground-truth labels live in a **separate file that is never ingested** — the
   engines must rediscover the attack; tests use the labels only to score them.
2. Ingestion normalizes six native formats onto one `SecurityEvent` shape, resolves
   hosts/IPs against the inventory, deduplicates on `external_id`, and builds a
   host-to-host `NetworkConnection` projection.
3. The analysis pipeline runs the engines and persists one `Incident` with its
   events, attack steps, graph edges, lateral movements, host risk scores and target
   predictions.
4. The dashboard reads it all back through `/api/v1/...`.

## Detection methodology

**Stage 1 — signals.** 15 small, named, configurable detectors attach scored
signals to individual events. Content detectors (encoded PowerShell, LSASS access,
recon, admin-share, credential-file, external auth, remote-exec parent, service
execution, sensitive DB access) run everywhere; windowed detectors (brute force,
port scan) and baseline-relative ones (first-seen remote logon, service-account
anomaly, novel DNS) compare the live window against a baseline built from earlier
days, so recurring benign admin behaviour isn't flagged. Per-event suspicion is a
noisy-OR over its signals.

**Stage 2 — correlation.** Signal events are linked pairwise on shared host, pivot
(movement onto another host), shared user / source IP, process lineage and
credential flow, weighted by a 30-minute exponential time decay. Union-find groups
them; a component becomes an incident only with ≥3 signals across ≥2 detector
families. Benign-looking projections (e.g. the C2 DNS/network counterparts) are then
pulled in as context with derived confidence.

Measured against ground truth: detection **precision 1.00 / recall 0.87 / zero false
positives**; correlation produces **exactly one incident**, precision 0.97, recall
0.93 — and stripping the attack leaves the benign data producing **zero incidents**.

## Attack reconstruction

- **Lateral movement** is anchored on successful remote authentication between two
  internal hosts whose source was already compromised, with the protocol taken from
  the nearest connection — so scans and probes are excluded. Result: `WEB-01 →
  APP-01` (WinRM) and `APP-01 → FILE-01` (SMB), both confidence 1.0.
- **Attack graph:** typed nodes (host/user/ip/process/domain) and edges
  (AUTHENTICATED_TO, CONNECTED_TO, RESOLVED, SPAWNED, ACCESSED, MOVED_TO) derived
  from the incident's events, with the movements as a MOVED_TO overlay. Clicking a
  node or edge shows its attributes, evidence and confidence.
- **Root cause:** each host is scored on earliest activity, external-source
  involvement, outbound vs inbound movement and mean correlation confidence. Result:
  **WEB-01**, confidence 0.98, with a templated explanation.

## MITRE mapping

A single configurable catalog maps technique IDs → name + tactic. Signals and
movements consolidate into a deduplicated, chronological 13-step kill chain
(T1110.001 → T1078 → T1059.001 → T1071.001 → T1003.001 → T1087.002 → T1046 →
T1021.006 → T1059.001 → T1213 → T1021.002 → T1569.002 → T1552.001). It is presented
as an **explainable prototype mapping from observed patterns, not authoritative
threat intelligence.**

## Risk & prediction methodology

- **Risk** is a transparent 0–100 score per host and for the incident. Each score is
  the exact sum of named factors (asset criticality, suspicious activity, credential
  access, lateral movement in/out, unusual authentication, sensitive data access,
  attack-chain proximity), each carrying its evidence. Weights live in
  `app/core/scoring.py` and are configurable. Demo incident: **90/critical**.
- **Next-target prediction** ranks uncompromised hosts by reachability (0.30),
  credential exposure (0.25), criticality (0.20), recent probe (0.15) and chain
  proximity (0.10). Result: **BACKUP-01 at 90/100**, because it's reachable from the
  compromised FILE-01 over SSH, the `svc_backup` credentials are exposed there, it's
  a crown-jewel asset, and it was just probed. Labelled a heuristic exposure ranking,
  not a guaranteed forecast.

## Screenshots

_Placeholders — open the dashboard at http://localhost:3000 after loading the demo._

- `docs/screenshots/dashboard.png` — full SOC dashboard
- `docs/screenshots/attack-graph.png` — interactive attack graph with node details
- `docs/screenshots/timeline.png` — ATT&CK timeline
- `docs/screenshots/assistant.png` — investigation assistant

## Setup (Docker)

```bash
docker compose up --build
```

- Dashboard: http://localhost:3000 → click **Load demo incident**
- API docs (OpenAPI): http://localhost:8000/docs
- PostgreSQL: `localhost:55432` (user/password/db: `threatlens`). Host ports are
  configurable via `THREATLENS_DB_PORT`, `THREATLENS_API_PORT`, `THREATLENS_WEB_PORT`.

To enable the LLM assistant, set `THREATLENS_LLM_API_KEY` (and optionally
`THREATLENS_LLM_MODEL`, default `claude-sonnet-5-5`) before `docker compose up`.
Without it, the deterministic evidence-based responder is used.

## Local development

Backend (Python 3.12+):

```bash
cd backend
python -m venv .venv && .venv/Scripts/activate     # or: source .venv/bin/activate
pip install -r requirements-dev.txt
docker compose up -d db                             # from the repo root
alembic upgrade head
python ../scripts/generate_dataset.py               # writes data/generated/*
python ../scripts/seed_database.py                  # seed inventory + ingest telemetry
uvicorn app.main:app --reload                       # use --port 8001 if Docker holds 8000
```

Frontend (Node 22+):

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to :8000
```

## API

OpenAPI UI at `/docs`. Key endpoints:

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/events/ingest` | Ingest JSON telemetry (`/ingest/file` for JSON/CSV upload) |
| GET | `/api/v1/events` · `/events/{id}` | Query normalized events |
| GET | `/api/v1/hosts` · `/hosts/{id}` | Inventory |
| POST | `/api/v1/analysis/run` | Run the analysis pipeline over ingested telemetry |
| GET | `/api/v1/incidents` · `/incidents/{id}` | Incident list / detail |
| GET | `/api/v1/incidents/{id}/timeline` | Ordered attack steps |
| GET | `/api/v1/incidents/{id}/graph` | Attack graph nodes + edges |
| GET | `/api/v1/incidents/{id}/mitre` | ATT&CK techniques + steps |
| GET | `/api/v1/incidents/{id}/risk` | Host risk breakdown |
| GET | `/api/v1/incidents/{id}/prediction` | Likely next target |
| POST | `/api/v1/investigate` | Ask the investigation assistant |
| POST | `/api/v1/demo/load` | Reset + seed + ingest + analyze (reproducible) |

## Demo

Click **Load demo incident** on the dashboard, or:

```bash
curl -X POST http://localhost:8000/api/v1/demo/load
# → {"incident_reference":"INC-1042","incidents":1,"events_analyzed":989}
```

It resets all telemetry and analysis, regenerates the synthetic scenario, ingests
989 events, and rebuilds the incident — **the same result every time**. The outcome:
INC-1042, critical, risk 90, root cause WEB-01, likely next target BACKUP-01.

## Tests

```bash
cd backend
pytest                                   # unit + integration on in-memory SQLite

# Also exercise the PostgreSQL migration test (it resets its own database):
docker compose exec db psql -U threatlens -c "CREATE DATABASE threatlens_test"   # once
TEST_DATABASE_URL=postgresql+psycopg://threatlens:threatlens@localhost:55432/threatlens_test pytest
```

Engine tests score precision/recall against the generator's ground truth; an
end-to-end test drives synthetic events → ingest → analyze → every incident endpoint
over HTTP; the demo test asserts reproducibility.

## Limitations

- Single synthetic scenario; detectors are generic but tuned against one dataset's
  benign look-alikes. Real-world logs are noisier and more varied.
- Batch re-analysis, not streaming (fine at prototype scale).
- The MITRE mapping and risk/prediction scores are explainable heuristics, not
  authoritative threat intelligence or forecasts.
- No authentication / multi-tenancy; intended as a demonstration prototype.
- The LLM assistant depends on an external API when enabled; the deterministic
  responder is the default and always available.

## Future improvements

- Streaming ingestion and incremental correlation.
- More log sources and detectors; data-driven detector tuning.
- Multiple concurrent incidents and cross-incident campaign linking.
- Analyst feedback loop to adjust weights; saved investigations.
- Authentication, RBAC, and audit logging for real deployments.

## Project structure

```
backend/   app/{api,core,models,schemas,repositories,services,engines,simulation}  tests/  alembic/
frontend/  src/{components,features,services,lib,types}
data/      generated/ raw/
scripts/   generate_dataset.py  seed_database.py
docs/      ARCHITECTURE.md
docker-compose.yml
```

Design rationale and the full schema are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
