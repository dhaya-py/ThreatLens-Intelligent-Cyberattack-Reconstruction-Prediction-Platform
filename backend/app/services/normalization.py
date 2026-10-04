"""Normalization layer: map each raw log format onto one `SecurityEvent` shape.

A normalizer is registered per `source` value and converts a raw record (from
JSON, or from CSV where every value is a string) into a `NormalizedEvent`. Host
resolution happens later in the ingestion service; normalizers only emit hostnames
and IP addresses as strings.

Design notes:
* Normalizers must tolerate both native-typed values (JSON) and strings (CSV),
  so numeric fields go through `_as_int` and missing values may be "" or None.
* Timestamps are parsed from each source's *native* field, never from any
  generator-added convenience field, so normalization is exercised honestly.
"""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.models.enums import EventOutcome, EventType


class NormalizationError(ValueError):
    """Raised when a record cannot be normalized (unknown source or bad shape)."""


@dataclass
class NormalizedEvent:
    timestamp: datetime
    event_type: str
    source: str
    external_id: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_hostname: str | None = None
    username: str | None = None
    process_name: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    domain: str | None = None
    protocol: str | None = None
    destination_port: int | None = None
    outcome: str | None = None
    metadata: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
    # Whether this event also represents a host-to-host connection.
    is_connection: bool = False
    bytes_sent: int | None = None


Normalizer = Callable[[dict], NormalizedEvent]
_REGISTRY: dict[str, Normalizer] = {}


def register(source: str) -> Callable[[Normalizer], Normalizer]:
    def decorator(func: Normalizer) -> Normalizer:
        _REGISTRY[source] = func
        return func

    return decorator


# --- helpers ----------------------------------------------------------------------


def _as_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))  # handles "1433", "1433.0", 1433
    except (TypeError, ValueError):
        return None


def _clean(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text in ("", "-"):
        return None
    return text


def _basename(path: object) -> str | None:
    text = _clean(path)
    if text is None:
        return None
    return re.split(r"[\\/]", text)[-1]


def _strip_domain(account: object) -> str | None:
    text = _clean(account)
    if text is None:
        return None
    return text.split("\\")[-1]


def _short_host(computer: object) -> str | None:
    text = _clean(computer)
    if text is None:
        return None
    return text.split(".")[0].upper()


def _parse_iso(value: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _parse_naive_utc(value: str, fmt: str) -> datetime:
    return datetime.strptime(value.strip(), fmt).replace(tzinfo=UTC)


def _external_id(raw: dict) -> str | None:
    ext = _clean(raw.get("external_id"))
    if ext:
        return ext
    # Deterministic fallback so re-ingesting identical records is idempotent.
    payload = {k: v for k, v in raw.items() if k != "external_id"}
    digest = hashlib.sha1(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
    return f"sha1:{digest}"


# --- Windows Security -------------------------------------------------------------

# LogonType 3 = network (SMB/WinRM), 10 = RemoteInteractive (RDP).
_REMOTE_LOGON_TYPES = {3, 10}


@register("windows_security")
def _windows_security(raw: dict) -> NormalizedEvent:
    event_id = _as_int(raw.get("EventID"))
    base = NormalizedEvent(
        timestamp=_parse_iso(raw["TimeCreated"]),
        event_type=EventType.AUTHENTICATION,
        source="windows_security",
        external_id=_external_id(raw),
        hostname=_short_host(raw.get("Computer")),
        raw=raw,
    )
    if event_id in (4624, 4625):
        logon_type = _as_int(raw.get("LogonType"))
        base.username = _strip_domain(raw.get("TargetUserName"))
        base.source_ip = _clean(raw.get("IpAddress"))
        base.outcome = EventOutcome.SUCCESS if event_id == 4624 else EventOutcome.FAILURE
        base.protocol = _logon_protocol(logon_type)
        base.metadata = {
            "event_id": event_id,
            "logon_type": logon_type,
            "auth_package": _clean(raw.get("AuthenticationPackageName")),
            "workstation": _clean(raw.get("WorkstationName")),
        }
        # A successful remote logon from a known IP is a host-to-host connection.
        if event_id == 4624 and logon_type in _REMOTE_LOGON_TYPES and base.source_ip:
            base.is_connection = True
            base.destination_hostname = base.hostname
            base.destination_port = _logon_port(logon_type)
        return base

    if event_id == 5145:
        base.event_type = EventType.FILE
        base.username = _strip_domain(raw.get("SubjectUserName"))
        base.source_ip = _clean(raw.get("IpAddress"))
        base.outcome = EventOutcome.SUCCESS
        base.metadata = {
            "event_id": event_id,
            "share": _clean(raw.get("ShareName")),
            "relative_target": _clean(raw.get("RelativeTargetName")),
            "access": _clean(raw.get("AccessList")),
        }
        return base

    raise NormalizationError(f"unsupported windows_security EventID {event_id}")


def _logon_protocol(logon_type: int | None) -> str | None:
    return {3: "smb", 10: "rdp"}.get(logon_type or -1)


def _logon_port(logon_type: int | None) -> int | None:
    return {3: 445, 10: 3389}.get(logon_type or -1)


# --- Sysmon -----------------------------------------------------------------------


@register("sysmon")
def _sysmon(raw: dict) -> NormalizedEvent:
    event_id = _as_int(raw.get("EventID"))
    base = NormalizedEvent(
        timestamp=_parse_naive_utc(raw["UtcTime"], "%Y-%m-%d %H:%M:%S.%f"),
        event_type=EventType.PROCESS,
        source="sysmon",
        external_id=_external_id(raw),
        hostname=_short_host(raw.get("Computer")),
        raw=raw,
    )
    if event_id == 1:
        base.username = _strip_domain(raw.get("User"))
        base.process_name = _basename(raw.get("Image"))
        base.parent_process = _basename(raw.get("ParentImage"))
        base.command_line = _clean(raw.get("CommandLine"))
        base.metadata = {"event_id": 1, "pid": _as_int(raw.get("ProcessId"))}
        return base

    if event_id == 3:
        base.event_type = EventType.NETWORK
        base.username = _strip_domain(raw.get("User"))
        base.process_name = _basename(raw.get("Image"))
        base.source_ip = _clean(raw.get("SourceIp"))
        base.destination_ip = _clean(raw.get("DestinationIp"))
        base.destination_port = _as_int(raw.get("DestinationPort"))
        base.protocol = _clean(raw.get("Protocol")) or "tcp"
        base.is_connection = True
        base.metadata = {"event_id": 3}
        return base

    if event_id == 22:
        base.event_type = EventType.DNS
        base.username = _strip_domain(raw.get("User"))
        base.process_name = _basename(raw.get("Image"))
        base.domain = _clean(raw.get("QueryName"))
        base.metadata = {"event_id": 22, "answer": _clean(raw.get("QueryResults"))}
        return base

    if event_id == 10:
        base.username = _strip_domain(raw.get("SourceUser"))
        base.process_name = _basename(raw.get("SourceImage"))
        base.metadata = {
            "event_id": 10,
            "target_image": _clean(raw.get("TargetImage")),
            "granted_access": _clean(raw.get("GrantedAccess")),
        }
        # Surface the target in the command_line so detection can match on it.
        base.command_line = f"process_access -> {_clean(raw.get('TargetImage'))}"
        return base

    raise NormalizationError(f"unsupported sysmon EventID {event_id}")


# --- Firewall ---------------------------------------------------------------------


@register("firewall")
def _firewall(raw: dict) -> NormalizedEvent:
    action = (_clean(raw.get("action")) or "allow").lower()
    return NormalizedEvent(
        timestamp=datetime.fromtimestamp(float(raw["ts"]), tz=UTC),
        event_type=EventType.NETWORK,
        source="firewall",
        external_id=_external_id(raw),
        source_ip=_clean(raw.get("src_ip")),
        destination_ip=_clean(raw.get("dst_ip")),
        destination_port=_as_int(raw.get("dst_port")),
        protocol=_clean(raw.get("proto")) or "tcp",
        outcome=EventOutcome.SUCCESS if action == "allow" else EventOutcome.FAILURE,
        is_connection=True,
        bytes_sent=_as_int(raw.get("bytes_sent")),
        metadata={
            "action": action,
            "rule": _clean(raw.get("rule")),
            "src_port": _as_int(raw.get("src_port")),
        },
        raw=raw,
    )


# --- DNS server -------------------------------------------------------------------


@register("dns_server")
def _dns_server(raw: dict) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=_parse_iso(raw["timestamp"]),
        event_type=EventType.DNS,
        source="dns_server",
        external_id=_external_id(raw),
        source_ip=_clean(raw.get("client_ip")),
        domain=_clean(raw.get("query")),
        metadata={
            "rcode": _clean(raw.get("rcode")),
            "answer": _clean(raw.get("answer")),
            "qtype": _clean(raw.get("qtype")),
        },
        raw=raw,
    )


# --- Linux auth (sshd) ------------------------------------------------------------

_SSH_ACCEPTED = re.compile(r"Accepted (\w+) for (\S+) from (\S+) port (\d+)")
_SSH_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
_SSH_CONNECTION = re.compile(r"Connection from (\S+) port (\d+) on (\S+) port (\d+)")


@register("linux_auth")
def _linux_auth(raw: dict) -> NormalizedEvent:
    message = str(raw.get("message", ""))
    base = NormalizedEvent(
        timestamp=_parse_iso(raw["timestamp"]),
        event_type=EventType.AUTHENTICATION,
        source="linux_auth",
        external_id=_external_id(raw),
        hostname=_short_host(raw.get("hostname")),
        protocol="ssh",
        destination_port=22,
        metadata={"program": _clean(raw.get("program")), "message": message},
        raw=raw,
    )
    if match := _SSH_ACCEPTED.search(message):
        base.outcome = EventOutcome.SUCCESS
        base.username = match.group(2)
        base.source_ip = match.group(3)
        base.is_connection = True
        base.destination_hostname = base.hostname
        return base
    if match := _SSH_FAILED.search(message):
        base.outcome = EventOutcome.FAILURE
        base.username = match.group(1)
        base.source_ip = match.group(2)
        return base
    if match := _SSH_CONNECTION.search(message):
        base.event_type = EventType.NETWORK
        base.source_ip = match.group(1)
        base.destination_ip = match.group(3)
        base.is_connection = True
        base.destination_hostname = base.hostname
        return base
    return base  # unrecognized sshd line: keep as context


# --- SQL Server audit -------------------------------------------------------------


@register("mssql_audit")
def _mssql_audit(raw: dict) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=_parse_mssql_time(raw["event_time"]),
        event_type=EventType.DATABASE,
        source="mssql_audit",
        external_id=_external_id(raw),
        hostname=_short_host(raw.get("server_instance_name")),
        username=_strip_domain(raw.get("server_principal_name")),
        source_ip=_clean(raw.get("client_ip")),
        destination_hostname=_short_host(raw.get("server_instance_name")),
        destination_port=1433,
        protocol="tds",
        outcome=EventOutcome.SUCCESS,
        is_connection=True,
        command_line=_clean(raw.get("statement")),
        metadata={
            "database": _clean(raw.get("database_name")),
            "object": _clean(raw.get("object_name")),
            "affected_rows": _as_int(raw.get("affected_rows")),
            "application": _clean(raw.get("application_name")),
        },
        raw=raw,
    )


def _parse_mssql_time(value: str) -> datetime:
    # SQL Server prints 7 fractional digits; Python handles at most 6.
    text = value.strip()
    if "." in text:
        head, frac = text.split(".", 1)
        text = f"{head}.{frac[:6]}"
        return _parse_naive_utc(text, "%Y-%m-%d %H:%M:%S.%f")
    return _parse_naive_utc(text, "%Y-%m-%d %H:%M:%S")


# --- entry point ------------------------------------------------------------------


def normalize(raw: dict) -> NormalizedEvent:
    source = _clean(raw.get("source"))
    if source is None:
        raise NormalizationError("record has no 'source' field")
    normalizer = _REGISTRY.get(source)
    if normalizer is None:
        raise NormalizationError(f"no normalizer registered for source '{source}'")
    return normalizer(raw)


def supported_sources() -> list[str]:
    return sorted(_REGISTRY)
