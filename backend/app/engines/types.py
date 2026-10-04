"""Plain dataclasses the engines operate on.

Engines never touch the ORM or the database: they take `EventView` snapshots and
return result dataclasses. This keeps them pure, deterministic and fast to test.
"""

from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network

# "Internal" = RFC1918 private space plus loopback/link-local. Everything else
# that parses as an IP is treated as external. We avoid ipaddress.is_private
# because recent Python also reports documentation ranges (RFC 5737, used by the
# synthetic attacker) as private, which would hide external access.
_INTERNAL_NETWORKS = tuple(
    ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
)

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
    source_host: str | None = None  # host resolved from source_ip (move origin)
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
        addr = ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETWORKS)


def is_external_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip_address(value)
    except ValueError:
        return False
    return not is_internal_ip(value)
