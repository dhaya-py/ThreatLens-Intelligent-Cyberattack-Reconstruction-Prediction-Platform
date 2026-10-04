"""Enumerations stored as varchar columns and validated at the application layer."""

from enum import StrEnum


class EventType(StrEnum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    DNS = "dns"
    NETWORK = "network"
    FILE = "file"
    DATABASE = "database"


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class PrivilegeLevel(StrEnum):
    STANDARD = "standard"
    ELEVATED = "elevated"
    ADMIN = "admin"
    DOMAIN_ADMIN = "domain_admin"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"


class EventRole(StrEnum):
    """How an event participates in an incident."""

    SIGNAL = "signal"  # carried a detection signal itself
    CONTEXT = "context"  # benign-looking, but directly tied to a signal event


class HostStatus(StrEnum):
    INITIAL_ENTRY = "initial_entry"
    COMPROMISED = "compromised"
    ACCESSED = "accessed"
    TARGETED = "targeted"
    OBSERVED = "observed"


class NodeType(StrEnum):
    HOST = "host"
    USER = "user"
    IP = "ip"
    PROCESS = "process"
    DOMAIN = "domain"


class Relationship(StrEnum):
    AUTHENTICATED_TO = "AUTHENTICATED_TO"
    CONNECTED_TO = "CONNECTED_TO"
    RESOLVED = "RESOLVED"
    SPAWNED = "SPAWNED"
    ACCESSED = "ACCESSED"
    MOVED_TO = "MOVED_TO"
