from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Host, User


@dataclass
class HostIndex:
    """Fast lookups from raw telemetry fields to inventory hosts."""

    by_name: dict[str, Host]  # keyed by UPPER short hostname
    by_ip: dict[str, Host]

    def resolve(self, hostname: str | None = None, ip: str | None = None) -> Host | None:
        if hostname:
            host = self.by_name.get(hostname.split(".")[0].upper())
            if host:
                return host
        if ip:
            return self.by_ip.get(ip)
        return None


class HostRepository:
    def __init__(self, db: Session):
        self.db = db

    def all(self) -> list[Host]:
        return list(self.db.scalars(select(Host).order_by(Host.hostname)))

    def get(self, host_id: int) -> Host | None:
        return self.db.get(Host, host_id)

    def index(self) -> HostIndex:
        hosts = self.all()
        return HostIndex(
            by_name={h.hostname.upper(): h for h in hosts},
            by_ip={h.ip_address: h for h in hosts},
        )

    def upsert(self, **fields) -> Host:
        host = self.db.scalar(select(Host).where(Host.hostname == fields["hostname"]))
        if host is None:
            host = Host(**fields)
            self.db.add(host)
        else:
            for key, value in fields.items():
                setattr(host, key, value)
        return host


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def all(self) -> list[User]:
        return list(self.db.scalars(select(User).order_by(User.username)))

    def upsert(self, **fields) -> User:
        user = self.db.scalar(select(User).where(User.username == fields["username"]))
        if user is None:
            user = User(**fields)
            self.db.add(user)
        else:
            for key, value in fields.items():
                setattr(user, key, value)
        return user
