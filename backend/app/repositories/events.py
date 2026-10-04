from collections.abc import Iterable, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models import Host, NetworkConnection, SecurityEvent


class EventRepository:
    def __init__(self, db: Session):
        self.db = db

    def existing_external_ids(self, external_ids: Iterable[str]) -> set[str]:
        ids = [e for e in external_ids if e]
        if not ids:
            return set()
        rows = self.db.scalars(
            select(SecurityEvent.external_id).where(SecurityEvent.external_id.in_(ids))
        )
        return set(rows)

    def add_all(self, events: Sequence[SecurityEvent]) -> None:
        self.db.add_all(events)

    def get(self, event_id: int) -> SecurityEvent | None:
        return self.db.get(
            SecurityEvent,
            event_id,
            options=[
                selectinload(SecurityEvent.host),
                selectinload(SecurityEvent.destination_host),
            ],
        )

    def count(self) -> int:
        return self.db.scalar(select(func.count()).select_from(SecurityEvent)) or 0

    def query(
        self,
        *,
        event_type: str | None = None,
        source: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SecurityEvent], int]:
        stmt = select(SecurityEvent).options(
            selectinload(SecurityEvent.host), selectinload(SecurityEvent.destination_host)
        )
        count_stmt = select(func.count()).select_from(SecurityEvent)

        if event_type:
            stmt = stmt.where(SecurityEvent.event_type == event_type)
            count_stmt = count_stmt.where(SecurityEvent.event_type == event_type)
        if source:
            stmt = stmt.where(SecurityEvent.source == source)
            count_stmt = count_stmt.where(SecurityEvent.source == source)
        if username:
            stmt = stmt.where(SecurityEvent.username == username)
            count_stmt = count_stmt.where(SecurityEvent.username == username)
        if hostname:
            stmt = stmt.join(SecurityEvent.host).where(
                func.upper(Host.hostname) == hostname.upper()
            )
            count_stmt = count_stmt.join(SecurityEvent.host).where(
                func.upper(Host.hostname) == hostname.upper()
            )

        total = self.db.scalar(count_stmt) or 0
        stmt = stmt.order_by(SecurityEvent.timestamp, SecurityEvent.id).limit(limit).offset(offset)
        return list(self.db.scalars(stmt)), total


class NetworkConnectionRepository:
    def __init__(self, db: Session):
        self.db = db

    def add_all(self, connections: Sequence[NetworkConnection]) -> None:
        self.db.add_all(connections)

    def count(self) -> int:
        return self.db.scalar(select(func.count()).select_from(NetworkConnection)) or 0
