from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models import SecurityEvent


class SecurityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    external_id: str | None
    timestamp: datetime
    event_type: str
    source: str
    host_id: int | None
    hostname: str | None = None
    destination_host_id: int | None
    destination_hostname: str | None = None
    username: str | None
    source_ip: str | None
    destination_ip: str | None
    process_name: str | None
    parent_process: str | None
    command_line: str | None
    domain: str | None
    protocol: str | None
    destination_port: int | None
    outcome: str | None
    metadata: dict[str, Any]

    @classmethod
    def from_event(cls, event: SecurityEvent) -> "SecurityEventRead":
        return cls(
            id=event.id,
            external_id=event.external_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            source=event.source,
            host_id=event.host_id,
            hostname=event.host.hostname if event.host else None,
            destination_host_id=event.destination_host_id,
            destination_hostname=(
                event.destination_host.hostname if event.destination_host else None
            ),
            username=event.username,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            process_name=event.process_name,
            parent_process=event.parent_process,
            command_line=event.command_line,
            domain=event.domain,
            protocol=event.protocol,
            destination_port=event.destination_port,
            outcome=event.outcome,
            metadata=event.event_metadata or {},
        )


class EventPage(BaseModel):
    items: list[SecurityEventRead]
    total: int
    limit: int
    offset: int


class IngestResponse(BaseModel):
    received: int
    ingested: int
    duplicates: int
    failed: int
    connections: int
    unresolved_hosts: list[str]
    by_source: dict[str, int]
    by_event_type: dict[str, int]
    errors: list[str]
