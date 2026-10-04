"""Deterministic dataset generator.

Combines two baseline days of benign telemetry with one incident day (benign +
the attack chain), assigns stable external IDs, and can export the raw records as
JSON and CSV plus a separate ground-truth file (labels + inventory) used only by
tests. The ground-truth file is never ingested.
"""

import csv
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from random import Random

from app.simulation import records as r
from app.simulation.benign import generate_benign
from app.simulation.inventory import HOSTS, USERS
from app.simulation.scenario import generate_scenario

SEED = 1042
BASE_DATE = datetime(2026, 3, 12, tzinfo=UTC)  # first baseline day
INCIDENT_DATE = datetime(2026, 3, 14, tzinfo=UTC)
BASELINE_DAYS = 2  # 03-12 and 03-13

# Stable column order for CSV export (union of all source fields).
CSV_COLUMNS = [
    "external_id",
    "source",
    "ts_utc",
    "TimeCreated",
    "UtcTime",
    "timestamp",
    "ts",
    "event_time",
    "EventID",
    "Computer",
    "hostname",
    "server_instance_name",
    "TargetUserName",
    "TargetDomainName",
    "SubjectUserName",
    "SubjectDomainName",
    "User",
    "SourceUser",
    "server_principal_name",
    "LogonType",
    "AuthenticationPackageName",
    "Status",
    "SubStatus",
    "IpAddress",
    "WorkstationName",
    "client_ip",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "proto",
    "action",
    "bytes_sent",
    "rule",
    "SourceIp",
    "SourcePort",
    "DestinationIp",
    "DestinationPort",
    "Protocol",
    "Initiated",
    "Image",
    "ParentImage",
    "CommandLine",
    "ProcessId",
    "ParentProcessId",
    "SourceImage",
    "SourceProcessId",
    "TargetImage",
    "GrantedAccess",
    "QueryName",
    "QueryResults",
    "query",
    "qtype",
    "rcode",
    "answer",
    "ShareName",
    "RelativeTargetName",
    "AccessList",
    "program",
    "pid",
    "message",
    "action_id",
    "database_name",
    "object_name",
    "statement",
    "affected_rows",
    "application_name",
]


@dataclass
class Dataset:
    events: list[dict]  # raw records (no labels), ready to ingest
    ground_truth: dict  # labels + inventory, for tests only

    def events_json(self) -> str:
        return json.dumps(self.events, indent=2, sort_keys=False)

    def ground_truth_json(self) -> str:
        return json.dumps(self.ground_truth, indent=2, sort_keys=False)

    def events_csv(self) -> str:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for event in self.events:
            writer.writerow(event)
        return buffer.getvalue()


def _finalize(raw: list[r.SimRecord]) -> Dataset:
    """Sort stably, assign external IDs, and split labels out of the payload."""
    # Stable order: (timestamp, source, original index) so ties never reorder.
    indexed = sorted(enumerate(raw), key=lambda pair: (pair[1].ts, pair[1].data["source"], pair[0]))

    events: list[dict] = []
    labels: dict[str, str] = {}
    label_counts: dict[str, int] = {}
    for seq, (_, record) in enumerate(indexed, start=1):
        external_id = f"evt-{seq:05d}"
        payload = {"external_id": external_id, "ts_utc": record.ts.isoformat(), **record.data}
        events.append(payload)
        if record.label:
            labels[external_id] = record.label
            label_counts[record.label] = label_counts.get(record.label, 0) + 1

    ground_truth = {
        "seed": SEED,
        "incident_date": INCIDENT_DATE.date().isoformat(),
        "root_host": "WEB-01",
        "likely_next_target": "BACKUP-01",
        "compromised_hosts": ["WEB-01", "APP-01", "DB-01", "FILE-01"],
        "attack_step_order": [
            "initial_access_bruteforce",
            "initial_access_success",
            "execution_powershell",
            "command_and_control",
            "credential_access_lsass",
            "discovery_account",
            "discovery_network",
            "lateral_movement_winrm",
            "remote_execution_app",
            "collection_database",
            "lateral_movement_smb",
            "credential_access_files",
            "probe_backup",
        ],
        "malicious_event_count": len(labels),
        "label_counts": label_counts,
        "labels": labels,
        "hosts": [h.to_dict() for h in HOSTS],
        "users": [u.to_dict() for u in USERS],
    }
    return Dataset(events=events, ground_truth=ground_truth)


def generate_dataset() -> Dataset:
    """Build the full deterministic dataset."""
    rng = Random(SEED)
    raw: list[r.SimRecord] = []

    for offset in range(BASELINE_DAYS):
        raw.extend(generate_benign(BASE_DATE + timedelta(days=offset), rng))

    # Incident day: benign backdrop plus the attack.
    raw.extend(generate_benign(INCIDENT_DATE, rng))
    raw.extend(generate_scenario(INCIDENT_DATE))

    return _finalize(raw)
