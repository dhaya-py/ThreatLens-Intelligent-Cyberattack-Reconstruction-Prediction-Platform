"""Explicit lateral-movement detection over an incident's events.

Each movement is *anchored on a successful remote authentication* between two
internal hosts:

    Host A --(successful SMB/RDP/WinRM/SSH logon)--> Host B
            [optionally followed by remote execution on Host B]

The hop is only reported when Host A was already compromised earlier in the
incident. Anchoring on authentication (rather than on any connection) keeps port
scans and unanswered probes out of the movement list, and the fine-grained
protocol/port is taken from the network connection closest in time to the logon.
Pure data access (SQL over 1433) has no interactive logon and is excluded by
design — it is collection, surfaced elsewhere.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.engines.detection import DEFAULT_DETECTION, DetectionResult, detect
from app.engines.types import EventView
from app.models.enums import EventOutcome, EventType

PORT_PROTOCOL = {445: "smb", 5985: "winrm", 5986: "winrm", 3389: "rdp", 22: "ssh", 135: "rpc"}
_REMOTE_PROTOCOLS = set(PORT_PROTOCOL.values())
_REMOTE_EXEC_PARENTS = {"wsmprovhost.exe", "psexesvc.exe", "wmiprvse.exe"}
_SERVICE_EXEC_IMAGES = {"psexesvc.exe", "paexec.exe"}
_BENIGN_PARENTS = {"services.exe", "taskeng.exe", "svchost.exe"}

_EXEC_WINDOW = timedelta(minutes=10)
_CONNECTION_WINDOW = timedelta(seconds=120)


@dataclass
class LateralMovement:
    source_host: str
    destination_host: str
    username: str | None
    protocol: str
    port: int | None
    timestamp: datetime
    confidence: float
    reason: str
    evidence: list[str] = field(default_factory=list)
    event_ids: list = field(default_factory=list)


def detect_lateral_movement(
    events: list[EventView], detection: DetectionResult | None = None
) -> list[LateralMovement]:
    events = sorted(events, key=lambda e: (e.timestamp, str(e.id)))
    detection = detection or detect(events, DEFAULT_DETECTION)
    signal_ids = detection.signal_event_ids(DEFAULT_DETECTION.signal_threshold)

    compromised_at = _compromise_times(events, signal_ids)
    connections = [
        e for e in events if e.event_type == EventType.NETWORK and e.source_host and e.dest_host
    ]

    movements: list[LateralMovement] = []
    for anchor in events:
        move = _movement_from_auth(anchor, events, connections, compromised_at, detection)
        if move is not None:
            movements.append(move)
            if move.destination_host not in compromised_at or (
                move.timestamp < compromised_at[move.destination_host]
            ):
                compromised_at[move.destination_host] = move.timestamp

    movements.sort(key=lambda m: m.timestamp)
    return movements


def _compromise_times(events, signal_ids) -> dict[str, datetime]:
    out: dict[str, datetime] = {}
    for e in events:
        if e.id in signal_ids and e.host and (e.host not in out or e.timestamp < out[e.host]):
            out[e.host] = e.timestamp
    return out


def _is_remote_auth(e: EventView) -> bool:
    if e.event_type != EventType.AUTHENTICATION or e.outcome != EventOutcome.SUCCESS:
        return False
    logon_type = e.metadata.get("logon_type")
    return logon_type in (3, 10) or e.protocol in _REMOTE_PROTOCOLS or e.source == "linux_auth"


def _movement_from_auth(
    anchor, events, connections, compromised_at, detection
) -> LateralMovement | None:
    if not _is_remote_auth(anchor):
        return None
    src, dst = anchor.source_host, (anchor.dest_host or anchor.host)
    if not src or not dst or src == dst:
        return None
    src_time = compromised_at.get(src)
    if src_time is None or src_time > anchor.timestamp:
        return None  # source not yet compromised

    protocol, port, conn = _nearest_connection(src, dst, anchor.timestamp, connections)
    if protocol is None:
        protocol, port = _protocol_from_logon(anchor)
    username = anchor.normalized_user

    exec_event = _find_remote_execution(dst, anchor.timestamp, username, events)
    first_seen = "first_seen_remote_logon" in detection.detectors_for(anchor.id)

    confidence = 0.45 + 0.15  # base + source compromised earlier
    reasons = [
        f"{src} authenticated to {dst} over {protocol.upper()}"
        + (f" as {username}" if username else "")
    ]
    if exec_event is not None:
        confidence += 0.25
        reasons.append(f"followed by remote execution on {dst} ({exec_event.process})")
    if first_seen:
        confidence += 0.15
        reasons.append("first-ever remote logon for this host pair")

    event_ids = [anchor.id]
    if conn is not None:
        event_ids.append(conn.id)
    if exec_event is not None:
        event_ids.append(exec_event.id)

    return LateralMovement(
        source_host=src,
        destination_host=dst,
        username=username,
        protocol=protocol,
        port=port,
        timestamp=anchor.timestamp,
        confidence=round(min(confidence, 1.0), 3),
        reason="; ".join(reasons),
        evidence=reasons,
        event_ids=event_ids,
    )


def _nearest_connection(src, dst, when, connections):
    best = None
    best_dt = _CONNECTION_WINDOW.total_seconds() + 1
    for c in connections:
        if c.source_host != src or c.dest_host != dst:
            continue
        proto = PORT_PROTOCOL.get(c.dest_port)
        if proto is None:
            continue
        dt = abs((c.timestamp - when).total_seconds())
        if dt <= _CONNECTION_WINDOW.total_seconds() and dt < best_dt:
            best, best_dt = c, dt
    if best is None:
        return None, None, None
    return PORT_PROTOCOL[best.dest_port], best.dest_port, best


def _protocol_from_logon(e: EventView) -> tuple[str, int | None]:
    if e.source == "linux_auth":
        return "ssh", 22
    logon_type = e.metadata.get("logon_type")
    if logon_type == 10:
        return "rdp", 3389
    if logon_type == 3:
        return "smb", 445
    return (e.protocol or "unknown"), e.dest_port


def _find_remote_execution(dst, start, username, events) -> EventView | None:
    for e in events:
        if e.event_type != EventType.PROCESS or e.host != dst:
            continue
        if not (start <= e.timestamp <= start + _EXEC_WINDOW):
            continue
        parent = (e.parent_process or "").lower()
        image = (e.process or "").lower()
        if parent in _REMOTE_EXEC_PARENTS or image in _SERVICE_EXEC_IMAGES:
            return e
        if username and e.username == username and parent not in _BENIGN_PARENTS:
            return e
    return None
