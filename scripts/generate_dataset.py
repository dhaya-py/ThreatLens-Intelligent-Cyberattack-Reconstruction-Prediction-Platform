"""Write the deterministic synthetic dataset to data/generated/.

Usage (from the backend/ directory so `app` is importable):

    python ../scripts/generate_dataset.py
    python ../scripts/generate_dataset.py --out ../data/generated
"""

import argparse
import sys
from pathlib import Path

# Allow running from the repo root too.
BACKEND = Path(__file__).resolve().parents[1] / "backend"
if BACKEND.exists() and str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.simulation.generator import generate_dataset  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ThreatLens synthetic telemetry.")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "data" / "generated",
        help="output directory (default: data/generated)",
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    dataset = generate_dataset()
    (args.out / "events.json").write_text(dataset.events_json(), encoding="utf-8")
    (args.out / "events.csv").write_text(dataset.events_csv(), encoding="utf-8")
    (args.out / "ground_truth.json").write_text(dataset.ground_truth_json(), encoding="utf-8")

    gt = dataset.ground_truth
    print(f"Wrote {len(dataset.events)} events to {args.out}")
    print(
        f"  malicious: {gt['malicious_event_count']}  benign: "
        f"{len(dataset.events) - gt['malicious_event_count']}"
    )
    print(f"  root host: {gt['root_host']}  likely next target: {gt['likely_next_target']}")


if __name__ == "__main__":
    main()
