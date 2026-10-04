"""Seed the database with inventory and (optionally) ingest generated telemetry.

Run after `alembic upgrade head`. Idempotent for inventory; events are
deduplicated on external_id, so re-running will not create duplicates.

    python ../scripts/seed_database.py                 # seed inventory + ingest data/generated
    python ../scripts/seed_database.py --no-events      # inventory only
    python ../scripts/seed_database.py --events path/to/events.json
"""

import argparse
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if BACKEND.exists() and str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.core.database import SessionLocal  # noqa: E402
from app.services.ingestion import IngestionService, parse_json  # noqa: E402
from app.services.seed import seed_inventory  # noqa: E402

DEFAULT_EVENTS = Path(__file__).resolve().parents[1] / "data" / "generated" / "events.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed ThreatLens inventory and telemetry.")
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--no-events", action="store_true", help="seed inventory only")
    args = parser.parse_args()

    with SessionLocal() as db:
        seeded = seed_inventory(db)
        db.commit()
        print(f"Seeded {seeded.hosts} hosts and {seeded.users} users.")

        if args.no_events:
            return
        if not args.events.exists():
            print(f"No events file at {args.events}; run scripts/generate_dataset.py first.")
            return

        records = parse_json(args.events.read_text(encoding="utf-8"))
        result = IngestionService(db).ingest(records)
        db.commit()
        print(
            f"Ingested {result.ingested} events "
            f"({result.duplicates} duplicates, {result.failed} failed, "
            f"{result.connections} connections)."
        )
        if result.unresolved_hosts:
            print(f"  unresolved hosts: {', '.join(result.unresolved_hosts)}")


if __name__ == "__main__":
    main()
