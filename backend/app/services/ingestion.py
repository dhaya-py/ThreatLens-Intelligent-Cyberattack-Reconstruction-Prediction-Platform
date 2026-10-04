"""Ingestion service: normalize raw records, resolve inventory, persist.

Accepts a list of raw dicts (parsed from JSON or CSV). For each record it:
  1. normalizes to the common `SecurityEvent` shape,
  2. resolves the observing host and any destination host from the inventory,
  3. deduplicates on `external_id` (within the batch and against the DB),
  4. builds a `NetworkConnection` projection for host-to-host events.

Everything is added in the caller's transaction; the caller commits.
"""

import csv
import io
import json
from dataclasses import asdict, dataclass, field

from sqlalchemy.orm import Session

from app.models import NetworkConnection, SecurityEvent
from app.repositories.events import EventRepository
from app.repositories.inventory import HostIndex, HostRepository
from app.services.normalization import NormalizationError, NormalizedEvent, normalize


@dataclass
class IngestionResult:
    received: int = 0
    ingested: int = 0
    duplicates: int = 0
    failed: int = 0
    connections: int = 0
    unresolved_hosts: set[str] = field(default_factory=set)
    by_source: dict[str, int] = field(default_factory=dict)
    by_event_type: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        data = asdict(self)
        data["unresolved_hosts"] = sorted(self.unresolved_hosts)
        data["errors"] = self.errors[:20]  # cap noise in the response
        return data


def parse_json(text: str) -> list[dict]:
    data = json.loads(text)
    if isinstance(data, dict) and "events" in data:
        data = data["events"]
    if not isinstance(data, list):
        raise ValueError("JSON payload must be a list of records (or {'events': [...]})")
    return data


def parse_csv(text: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    # Drop empty-string cells so normalizers treat them as missing.
    return [{k: v for k, v in row.items() if v not in (None, "")} for row in reader]


class IngestionService:
    def __init__(self, db: Session):
        self.db = db
        self.events = EventRepository(db)
        self.hosts = HostRepository(db)

    def ingest(self, records: list[dict]) -> IngestionResult:
        result = IngestionResult(received=len(records))
        index = self.hosts.index()

        normalized: list[NormalizedEvent] = []
        for raw in records:
            try:
                normalized.append(normalize(raw))
            except (NormalizationError, KeyError, ValueError) as exc:
                result.failed += 1
                result.errors.append(f"{raw.get('source', '?')}: {exc}")

        # Deduplicate: within the batch, then against what is already stored.
        batch_ids = [n.external_id for n in normalized if n.external_id]
        existing = self.events.existing_external_ids(batch_ids)
        seen: set[str] = set()

        new_events: list[tuple[NormalizedEvent, SecurityEvent]] = []
        for norm in normalized:
            ext = norm.external_id
            if ext and (ext in existing or ext in seen):
                result.duplicates += 1
                continue
            if ext:
                seen.add(ext)
            new_events.append((norm, self._to_model(norm, index, result)))

        self.events.add_all([model for _, model in new_events])
        self.db.flush()  # assign primary keys for the connection projection

        connections = [
            conn
            for norm, model in new_events
            if (conn := self._to_connection(norm, model, index)) is not None
        ]
        self.db.add_all(connections)

        result.ingested = len(new_events)
        result.connections = len(connections)
        for norm, _ in new_events:
            result.by_source[norm.source] = result.by_source.get(norm.source, 0) + 1
            result.by_event_type[norm.event_type] = result.by_event_type.get(norm.event_type, 0) + 1
        return result

    def _to_model(
        self, norm: NormalizedEvent, index: HostIndex, result: IngestionResult
    ) -> SecurityEvent:
        host = index.resolve(hostname=norm.hostname, ip=norm.source_ip)
        if host is None and norm.hostname:
            result.unresolved_hosts.add(norm.hostname)
        dest = index.resolve(hostname=norm.destination_hostname, ip=norm.destination_ip)

        return SecurityEvent(
            external_id=norm.external_id,
            timestamp=norm.timestamp,
            event_type=norm.event_type,
            source=norm.source,
            host_id=host.id if host else None,
            destination_host_id=dest.id if dest else None,
            username=norm.username,
            source_ip=norm.source_ip,
            destination_ip=norm.destination_ip,
            process_name=norm.process_name,
            parent_process=norm.parent_process,
            command_line=norm.command_line,
            domain=norm.domain,
            protocol=norm.protocol,
            destination_port=norm.destination_port,
            outcome=norm.outcome,
            raw_log=json.dumps(norm.raw, sort_keys=True),
            event_metadata=norm.metadata,
        )

    def _to_connection(
        self, norm: NormalizedEvent, model: SecurityEvent, index: HostIndex
    ) -> NetworkConnection | None:
        if not norm.is_connection:
            return None
        src = index.resolve(ip=norm.source_ip) or (model.host if model.host_id else None)
        dst = index.resolve(hostname=norm.destination_hostname, ip=norm.destination_ip)
        if dst is None and model.destination_host_id:
            dst = index.by_ip.get(norm.destination_ip or "")
        # Keep only connections where at least the destination host is known;
        # these feed lateral-movement and prediction (internal reachability).
        if dst is None:
            return None
        return NetworkConnection(
            event_id=model.id,
            timestamp=norm.timestamp,
            source_host_id=src.id if src else None,
            destination_host_id=dst.id,
            source_ip=norm.source_ip,
            destination_ip=norm.destination_ip or dst.ip_address,
            username=norm.username,
            protocol=norm.protocol,
            port=norm.destination_port,
            bytes_sent=norm.bytes_sent,
        )
