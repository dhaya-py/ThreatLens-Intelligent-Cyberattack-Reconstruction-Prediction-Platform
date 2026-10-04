# ThreatLens

Intelligent cyberattack reconstruction and prediction platform. ThreatLens turns
fragmented security telemetry (authentication, DNS, process and network events)
into a reconstructed attack timeline, an interactive incident graph, MITRE ATT&CK
mapping, lateral-movement detection, root-cause identification, risk scoring and
an explainable "Likely Next Target".

> Work in progress. The design baseline is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
> The full README (methodology, screenshots, API reference, demo script) lands in Phase 12.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Architecture, repo structure, Docker, models, migrations | done |
| 2 | Synthetic telemetry generator (6 log formats, deterministic attack + benign noise) | done |
| 3 | Ingestion (JSON/CSV) + normalization | next |
| 4–9 | Correlation, graph & lateral movement, MITRE, root cause & risk, prediction, APIs | planned |
| 10–12 | React SOC dashboard, AI investigation assistant, testing & demo mode | planned |

## Quick start (Docker)

```bash
docker compose up --build
```

- Dashboard: http://localhost:3000
- API docs (OpenAPI): http://localhost:8000/docs
- PostgreSQL: `localhost:55432` (user/password/db: `threatlens`). Host ports can be overridden with `THREATLENS_DB_PORT`, `THREATLENS_API_PORT` and `THREATLENS_WEB_PORT`.

## Local development

Backend (Python 3.12+):

```bash
cd backend
python -m venv .venv && .venv/Scripts/activate    # or: source .venv/bin/activate
pip install -r requirements-dev.txt
docker compose up -d db                            # from the repo root
alembic upgrade head
uvicorn app.main:app --reload
```

Frontend (Node 22+):

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to :8000
```

## Tests

```bash
cd backend
pytest                                   # unit tests on in-memory SQLite

# Also run the PostgreSQL migration test. It resets its database, so use a dedicated one:
docker compose exec db psql -U threatlens -c "CREATE DATABASE threatlens_test"   # once
TEST_DATABASE_URL=postgresql+psycopg://threatlens:threatlens@localhost:55432/threatlens_test pytest
```
