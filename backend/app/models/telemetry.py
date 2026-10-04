from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.inventory import Host


class SecurityEvent(Base):
    """A normalized telemetry event. All log sources are mapped onto this shape."""

    __tablename__ = "security_events"
    __table_args__ = (Index("ix_security_events_host_id_timestamp", "host_id", "timestamp"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    # Source-system identifier; makes ingestion idempotent.
    external_id: Mapped[str | None] = mapped_column(String(128), unique=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(64))

    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"))
    destination_host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"))
    username: Mapped[str | None] = mapped_column(String(128), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45))

    process_name: Mapped[str | None] = mapped_column(String(256))
    parent_process: Mapped[str | None] = mapped_column(String(256))
    command_line: Mapped[str | None] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(String(253))
    protocol: Mapped[str | None] = mapped_column(String(16))
    destination_port: Mapped[int | None] = mapped_column(Integer)
    outcome: Mapped[str | None] = mapped_column(String(16))

    raw_log: Mapped[str | None] = mapped_column(Text)
    # `metadata` is reserved on declarative classes, so the attribute is renamed.
    event_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", default=dict)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    host: Mapped[Host | None] = relationship(foreign_keys=[host_id])
    destination_host: Mapped[Host | None] = relationship(foreign_keys=[destination_host_id])

    def __repr__(self) -> str:
        return f"<SecurityEvent {self.id} {self.event_type} {self.timestamp:%H:%M:%S}>"


class NetworkConnection(Base):
    """Host-to-host projection of network/auth events with both endpoints resolved."""

    __tablename__ = "network_connections"
    __table_args__ = (
        Index("ix_network_connections_src_dst", "source_host_id", "destination_host_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("security_events.id", ondelete="CASCADE"), index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"))
    destination_host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    username: Mapped[str | None] = mapped_column(String(128))
    protocol: Mapped[str | None] = mapped_column(String(16))
    port: Mapped[int | None] = mapped_column(Integer)
    bytes_sent: Mapped[int | None] = mapped_column(BigInteger)

    event: Mapped[SecurityEvent | None] = relationship()
    source_host: Mapped[Host | None] = relationship(foreign_keys=[source_host_id])
    destination_host: Mapped[Host | None] = relationship(foreign_keys=[destination_host_id])
