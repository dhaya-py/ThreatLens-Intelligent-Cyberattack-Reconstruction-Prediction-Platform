"""Plain dataclasses the engines operate on.

Engines never touch the ORM or the database: they take `EventView` snapshots and
return result dataclasses. This keeps them pure, deterministic and fast to test.
"""

from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address

# Accounts that should never count as "the same user" when correlating.
SYSTEM_ACCOUNTS = frozenset({"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "-"})


@dataclass(frozen=True)
class EventView:
    """Everything an engine needs about one security event."""

    id: int | str
    timestamp: datetime
    event_type: str
    source: str
    host: str | None = None
    dest_host: str | None = None
    username: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    process: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    domain: str | None = None
    protocol: str | None = None
    dest_port: int | None = None
    outcome: str | None = None
    metadata: dict = field(default_factory=dict)

    @property
    def normalized_user(self) -> str | None:
        if not self.username or self.username.upper() in SYSTEM_ACCOUNTS:
            return None
        return self.username


@dataclass(frozen=True)
class Signal:
    """A detection hit on a single event."""

    detector: str
    score: float  # 0..1
    reason: str
    tactic: str
    technique_id: str | None = None


def is_internal_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ip_address(value).is_private
    except ValueError:
        return False


def is_external_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return not ip_address(value).is_private
    except ValueError:
        return False
