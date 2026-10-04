"""MITRE ATT&CK mapping: consolidate detection signals and lateral movements into
an ordered, deduplicated sequence of attack steps (the incident timeline).

This is an explainable *prototype* mapping from observed event patterns to ATT&CK
techniques — not authoritative threat intelligence. The catalog below is the
single place that maps a technique ID to its name and tactic, and is intended to
be edited/extended.
"""

from dataclasses import dataclass, field
from datetime import datetime

from app.engines.detection import DEFAULT_DETECTION, DetectionResult, detect
from app.engines.lateral_movement import LateralMovement
from app.engines.types import EventView

# --- configurable technique catalog ----------------------------------------------

# technique_id -> (technique_name, tactic)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1087.002": ("Account Discovery: Domain Account", "Discovery"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.003": ("Remote Services: Distributed COM", "Lateral Movement"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1021.006": ("Remote Services: Windows Remote Management", "Lateral Movement"),
    "T1569.002": ("System Services: Service Execution", "Execution"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1213": ("Data from Information Repositories", "Collection"),
}

# Chronology is primary, but tactic order breaks ties at the same timestamp.
TACTIC_ORDER: dict[str, int] = {
    tactic: i
    for i, tactic in enumerate(
        [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ]
    )
}

# Detectors whose meaning is represented instead by the lateral-movement overlay.
_MOVEMENT_OWNED_DETECTORS = {
    "first_seen_remote_logon",
    "remote_exec_parent",
    "service_account_anomaly",
}

_PROTOCOL_TECHNIQUE = {
    "winrm": "T1021.006",
    "smb": "T1021.002",
    "rdp": "T1021.001",
    "ssh": "T1021.004",
    "rpc": "T1021.003",
}


@dataclass
class AttackStep:
    sequence: int
    timestamp: datetime
    host: str | None
    tactic: str
    technique_id: str
    technique_name: str
    confidence: float
    description: str
    evidence: list[str] = field(default_factory=list)
    event_ids: list = field(default_factory=list)


@dataclass
class _StepBuilder:
    timestamp: datetime
    host: str | None
    technique_id: str
    confidence: float
    evidence: list[str]
    event_ids: list

    def merge(self, timestamp, confidence, reason, event_ids) -> None:
        self.timestamp = min(self.timestamp, timestamp)
        self.confidence = max(self.confidence, confidence)
        if reason and reason not in self.evidence:
            self.evidence.append(reason)
        for eid in event_ids:
            if eid not in self.event_ids:
                self.event_ids.append(eid)


def map_attack_steps(
    incident_events: list[EventView],
    detection: DetectionResult | None = None,
    movements: list[LateralMovement] | None = None,
) -> list[AttackStep]:
    detection = detection or detect(incident_events, DEFAULT_DETECTION)
    movements = movements or []
    by_id = {e.id: e for e in incident_events}
    signal_ids = detection.signal_event_ids(DEFAULT_DETECTION.signal_threshold)

    builders: dict[tuple[str, str | None], _StepBuilder] = {}

    def add(technique_id, host, timestamp, confidence, reason, event_ids):
        if technique_id not in TECHNIQUES:
            return
        key = (technique_id, host)
        builder = builders.get(key)
        if builder is None:
            builders[key] = _StepBuilder(
                timestamp,
                host,
                technique_id,
                confidence,
                [reason] if reason else [],
                list(event_ids),
            )
        else:
            builder.merge(timestamp, confidence, reason, event_ids)

    # Signal-derived steps.
    for eid in signal_ids:
        event = by_id.get(eid)
        if event is None:
            continue
        confidence = detection.suspicion.get(eid, 0.0)
        for signal in detection.signals.get(eid, ()):
            if signal.detector in _MOVEMENT_OWNED_DETECTORS or not signal.technique_id:
                continue
            add(signal.technique_id, event.host, event.timestamp, confidence, signal.reason, [eid])

    # Lateral-movement steps (own the Lateral Movement tactic).
    for m in movements:
        technique_id = _PROTOCOL_TECHNIQUE.get(m.protocol, "T1021")
        add(technique_id, m.destination_host, m.timestamp, m.confidence, m.reason, m.event_ids)

    steps = _finalize(builders)
    return steps


def _finalize(builders: dict) -> list[AttackStep]:
    ordered = sorted(
        builders.values(),
        key=lambda b: (b.timestamp, TACTIC_ORDER.get(TECHNIQUES[b.technique_id][1], 99)),
    )
    steps: list[AttackStep] = []
    for i, b in enumerate(ordered, start=1):
        name, tactic = TECHNIQUES[b.technique_id]
        description = f"{name} on {b.host}" if b.host else name
        if b.evidence:
            description = f"{name}: {b.evidence[0]}"
        steps.append(
            AttackStep(
                sequence=i,
                timestamp=b.timestamp,
                host=b.host,
                tactic=tactic,
                technique_id=b.technique_id,
                technique_name=name,
                confidence=round(b.confidence, 3),
                description=description,
                evidence=b.evidence[:5],
                event_ids=b.event_ids[:25],
            )
        )
    return steps


def techniques_summary(steps: list[AttackStep]) -> list[dict]:
    """Distinct techniques observed, for the dashboard ATT&CK panel."""
    seen: dict[str, dict] = {}
    for step in steps:
        entry = seen.setdefault(
            step.technique_id,
            {
                "technique_id": step.technique_id,
                "technique_name": step.technique_name,
                "tactic": step.tactic,
                "confidence": step.confidence,
                "hosts": [],
            },
        )
        entry["confidence"] = max(entry["confidence"], step.confidence)
        if step.host and step.host not in entry["hosts"]:
            entry["hosts"].append(step.host)
    return sorted(seen.values(), key=lambda t: TACTIC_ORDER.get(t["tactic"], 99))
