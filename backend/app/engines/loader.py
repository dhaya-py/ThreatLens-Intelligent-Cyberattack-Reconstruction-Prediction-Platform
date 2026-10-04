"""Build `EventView` snapshots for the engines.

Two sources:
* `from_raw_records` normalizes raw telemetry and resolves hostnames against the
  simulation inventory — a database-free path used by engine tests and by any
  "analyze without persisting" flow.
* `from_db_events` adapts persisted `SecurityEvent` rows (with their host
  relationships loaded) for the analysis pipeline.
"""

from collections.abc import Iterable, Sequence

from app.engines.types import EventView
from app.models import SecurityEvent
from app.services.normalization import normalize
from app.simulation.inventory import HOSTS


def _inventory_index() -> tuple[dict[str, str], dict[str, str]]:
    by_name = {h.hostname.upper(): h.hostname for h in HOSTS}
    by_ip = {h.ip_address: h.hostname for h in HOSTS}
    return by_name, by_ip


def from_raw_records(records: Iterable[dict]) -> list[EventView]:
    by_name, by_ip = _inventory_index()

    def resolve(hostname: str | None, ip: str | None) -> str | None:
        if hostname and (name := by_name.get(hostname.split(".")[0].upper())):
            return name
        if ip and ip in by_ip:
            return by_ip[ip]
        return None

    views: list[EventView] = []
    for raw in records:
        try:
            n = normalize(raw)
        except Exception:  # noqa: BLE001 - skip unparseable records during analysis
            continue
        views.append(
            EventView(
                id=n.external_id or f"idx-{len(views)}",
                timestamp=n.timestamp,
                event_type=n.event_type,
                source=n.source,
                host=resolve(n.hostname, n.source_ip),
                dest_host=resolve(n.destination_hostname, n.destination_ip),
                source_host=resolve(None, n.source_ip),
                username=n.username,
                source_ip=n.source_ip,
                dest_ip=n.destination_ip,
                process=n.process_name,
                parent_process=n.parent_process,
                command_line=n.command_line,
                domain=n.domain,
                protocol=n.protocol,
                dest_port=n.destination_port,
                outcome=n.outcome,
                metadata=n.metadata,
            )
        )
    return views


def from_db_events(events: Sequence[SecurityEvent]) -> list[EventView]:
    # Build an IP -> hostname map from the hosts referenced by these events, so a
    # move's origin host can be resolved from source_ip.
    by_ip: dict[str, str] = {}
    for e in events:
        for host in (e.host, e.destination_host):
            if host:
                by_ip[host.ip_address] = host.hostname

    return [
        EventView(
            id=e.id,
            timestamp=e.timestamp,
            event_type=e.event_type,
            source=e.source,
            host=e.host.hostname if e.host else None,
            dest_host=e.destination_host.hostname if e.destination_host else None,
            source_host=by_ip.get(e.source_ip) if e.source_ip else None,
            username=e.username,
            source_ip=e.source_ip,
            dest_ip=e.destination_ip,
            process=e.process_name,
            parent_process=e.parent_process,
            command_line=e.command_line,
            domain=e.domain,
            protocol=e.protocol,
            dest_port=e.destination_port,
            outcome=e.outcome,
            metadata=e.event_metadata or {},
        )
        for e in events
    ]
