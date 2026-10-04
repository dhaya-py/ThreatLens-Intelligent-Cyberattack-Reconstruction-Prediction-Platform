"""Seed inventory (hosts and users) from the simulation definition.

Host resolution during ingestion needs the inventory to exist first. This is
idempotent: it upserts, so re-seeding does not create duplicates.
"""

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.repositories.inventory import HostRepository, UserRepository
from app.simulation.inventory import HOSTS, USERS


@dataclass
class SeedResult:
    hosts: int
    users: int


def seed_inventory(db: Session) -> SeedResult:
    host_repo = HostRepository(db)
    user_repo = UserRepository(db)

    for host in HOSTS:
        host_repo.upsert(
            hostname=host.hostname,
            ip_address=host.ip_address,
            operating_system=host.operating_system,
            department=host.department,
            criticality=host.criticality,
            role=host.role,
            network_zone=host.network_zone,
        )
    for user in USERS:
        user_repo.upsert(**user.to_dict())

    db.flush()
    return SeedResult(hosts=len(HOSTS), users=len(USERS))
