from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import NetworkConnection, SecurityEvent
from app.models.enums import EventType
from app.repositories.inventory import HostRepository
from app.services.ingestion import IngestionService, parse_csv
from app.simulation.generator import generate_dataset


def _ingest_full(db: Session) -> tuple[IngestionService, object]:
    dataset = generate_dataset()
    service = IngestionService(db)
    result = service.ingest(dataset.events)
    db.commit()
    return service, result


def test_full_dataset_ingests_without_failures(seeded_db: Session) -> None:
    dataset = generate_dataset()
    _, result = _ingest_full(seeded_db)
    assert result.received == len(dataset.events)
    assert result.ingested == len(dataset.events)
    assert result.failed == 0
    # Every log source should survive normalization.
    assert set(result.by_source) == {
        "windows_security",
        "sysmon",
        "firewall",
        "dns_server",
        "linux_auth",
        "mssql_audit",
    }


def test_ingestion_resolves_hosts(seeded_db: Session) -> None:
    _ingest_full(seeded_db)
    # No internal host should be left unresolved after seeding inventory.
    web_events = seeded_db.scalars(
        select(SecurityEvent).where(SecurityEvent.event_type == EventType.DATABASE)
    ).all()
    assert web_events
    assert all(e.host_id is not None for e in web_events)  # DB events resolve to DB-01


def test_ingestion_builds_network_connections(seeded_db: Session) -> None:
    _, result = _ingest_full(seeded_db)
    assert result.connections > 0
    hosts = HostRepository(seeded_db).index()
    web, app = hosts.by_name["WEB-01"], hosts.by_name["APP-01"]
    # The WEB-01 -> APP-01 WinRM move should appear as a resolved connection.
    move = seeded_db.scalars(
        select(NetworkConnection).where(
            NetworkConnection.source_host_id == web.id,
            NetworkConnection.destination_host_id == app.id,
            NetworkConnection.port == 5985,
        )
    ).first()
    assert move is not None


def test_ingestion_is_idempotent(seeded_db: Session) -> None:
    dataset = generate_dataset()
    service = IngestionService(seeded_db)
    first = service.ingest(dataset.events)
    seeded_db.commit()
    second = service.ingest(dataset.events)
    seeded_db.commit()
    assert first.ingested == len(dataset.events)
    assert second.ingested == 0
    assert second.duplicates == len(dataset.events)
    assert service.events.count() == len(dataset.events)


def test_csv_and_json_ingestion_agree(seeded_db: Session) -> None:
    dataset = generate_dataset()
    rows = parse_csv(dataset.events_csv())
    result = IngestionService(seeded_db).ingest(rows)
    seeded_db.commit()
    assert result.failed == 0
    assert result.ingested == len(dataset.events)


def test_malformed_record_is_counted_not_fatal(seeded_db: Session) -> None:
    records = [
        {"source": "firewall", "ts": "not-a-number", "src_ip": "1.1.1.1"},
        {"source": "unknown_source"},
    ]
    result = IngestionService(seeded_db).ingest(records)
    seeded_db.commit()
    assert result.failed == 2
    assert result.ingested == 0
