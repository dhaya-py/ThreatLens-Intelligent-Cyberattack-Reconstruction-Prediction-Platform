"""Stage 1 of correlation: attach detection *signals* to individual events.

Each detector is a small, named rule. Content-based detectors (encoded
PowerShell, LSASS access, recon, ...) run over every event; benign data simply
doesn't match them. First-seen / baseline-profile detectors (novel remote logon,
service-account anomaly, novel DNS) compare the "live" window against a baseline
built from earlier days, so recurring benign admin behaviour is not flagged.

Event suspicion is combined with a noisy-OR over its signals. Events at or above
`signal_threshold` become signal events that feed the correlation stage.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.engines.config import DEFAULT_DETECTION, DetectionConfig
from app.engines.types import EventView, Signal, is_external_ip
from app.models.enums import EventOutcome, EventType

# --- patterns ---------------------------------------------------------------------

_ENCODED_PS = re.compile(
    r"-enc(?:odedcommand)?\b|-e\b|\bIEX\b|invoke-expression|-w\s+hidden|-nop", re.IGNORECASE
)
_PS_IMAGE = re.compile(r"powershell(\.exe)?$|pwsh(\.exe)?$", re.IGNORECASE)
_LSASS = re.compile(r"lsass|minidump|sekurlsa|comsvcs\.dll|procdump", re.IGNORECASE)
_RECON = re.compile(
    r"net\s+(user|group|localgroup).*/domain|net\s+group\s+\"domain admins\"|"
    r"\bnltest\b|whoami\s+/all|\bnet\s+view\b|\bquser\b",
    re.IGNORECASE,
)
_ADMIN_SHARE = re.compile(r"\b(ADMIN\$|C\$|IPC\$)", re.IGNORECASE)
_CRED_FILE = re.compile(r"pass|cred|secret|unattend|\.kdbx|config.*\.xml|\.ps1xml", re.IGNORECASE)
_REMOTE_EXEC_PARENTS = {"wsmprovhost.exe", "psexesvc.exe", "wmiprvse.exe", "mmc.exe"}
_SERVICE_EXEC_IMAGES = {"psexesvc.exe", "paexec.exe"}
_REMOTE_PROTOCOLS = {"smb", "rdp", "winrm", "ssh", "rpc", "wmi"}
_SENSITIVE_OBJECT = re.compile(
    r"customer|card|ssn|salary|payroll|account|credential|secret", re.IGNORECASE
)
DB_SENSITIVE_ROWS = 1000


@dataclass
class DetectionResult:
    signals: dict = field(default_factory=lambda: defaultdict(list))  # event_id -> [Signal]
    suspicion: dict = field(default_factory=dict)  # event_id -> float

    def signal_event_ids(self, threshold: float) -> set:
        return {eid for eid, score in self.suspicion.items() if score >= threshold}

    def detectors_for(self, event_id) -> set:
        return {s.detector for s in self.signals.get(event_id, ())}


def _noisy_or(scores: list[float]) -> float:
    product = 1.0
    for s in scores:
        product *= 1.0 - s
    return 1.0 - product


def _is_powershell(event: EventView) -> bool:
    return bool(event.process and _PS_IMAGE.search(event.process))


def _baseline_cutoff(events: list[EventView]) -> datetime:
    """Start of the last calendar day present; earlier events form the baseline."""
    last = max(e.timestamp for e in events)
    return last.replace(hour=0, minute=0, second=0, microsecond=0)


def detect(events: list[EventView], config: DetectionConfig = DEFAULT_DETECTION) -> DetectionResult:
    events = sorted(events, key=lambda e: (e.timestamp, str(e.id)))
    result = DetectionResult()

    def emit(event: EventView, detector: str, reason: str, tactic: str, technique: str | None):
        result.signals[event.id].append(
            Signal(detector, config.scores[detector], reason, tactic, technique)
        )

    cutoff = _baseline_cutoff(events) if events else None
    baseline = [e for e in events if cutoff and e.timestamp < cutoff]
    live = [e for e in events if cutoff and e.timestamp >= cutoff]

    _detect_content(events, emit)
    _detect_bruteforce(events, config, emit)
    _detect_portscan(events, config, emit)
    _detect_first_seen_logon(baseline, live, emit)
    _detect_service_account(baseline, live, emit)
    _detect_suspicious_dns(baseline, live, result, emit)

    for event in events:
        scores = [s.score for s in result.signals.get(event.id, ())]
        if scores:
            result.suspicion[event.id] = round(_noisy_or(scores), 4)
    return result


# --- content-based detectors ------------------------------------------------------


def _detect_content(events, emit) -> None:
    for e in events:
        cmd = e.command_line or ""
        if _is_powershell(e) and _ENCODED_PS.search(cmd):
            emit(
                e,
                "encoded_powershell",
                f"obfuscated PowerShell: {cmd[:80]}",
                "Execution",
                "T1059.001",
            )
        if _LSASS.search(cmd):
            emit(
                e,
                "lsass_access",
                f"credential dumping indicator: {cmd[:80]}",
                "Credential Access",
                "T1003.001",
            )
        if _RECON.search(cmd):
            emit(
                e, "recon_commands", f"domain reconnaissance: {cmd[:80]}", "Discovery", "T1087.002"
            )
        if e.process and e.process.lower() in _SERVICE_EXEC_IMAGES:
            emit(
                e,
                "service_execution",
                f"service-based remote execution: {e.process}",
                "Lateral Movement",
                "T1569.002",
            )
        if e.parent_process and e.parent_process.lower() in _REMOTE_EXEC_PARENTS:
            emit(
                e,
                "remote_exec_parent",
                f"process spawned by remote-exec handler {e.parent_process}",
                "Lateral Movement",
                "T1021",
            )

        if e.event_type == EventType.FILE:
            share = str(e.metadata.get("share") or "")
            target = str(e.metadata.get("relative_target") or "")
            if _ADMIN_SHARE.search(share):
                emit(
                    e,
                    "admin_share_access",
                    f"administrative share access: {share}",
                    "Lateral Movement",
                    "T1021.002",
                )
            if _CRED_FILE.search(target):
                emit(
                    e,
                    "credential_file_access",
                    f"sensitive file access: {target}",
                    "Credential Access",
                    "T1552.001",
                )

        if (
            e.event_type == EventType.AUTHENTICATION
            and e.outcome == EventOutcome.SUCCESS
            and is_external_ip(e.source_ip)
            and e.metadata.get("logon_type") in (3, 10)
        ):
            emit(
                e,
                "external_auth",
                f"successful remote logon from external IP {e.source_ip}",
                "Initial Access",
                "T1078",
            )

        if e.event_type == EventType.DATABASE:
            rows = e.metadata.get("affected_rows") or 0
            obj = str(e.metadata.get("object") or "")
            if rows >= DB_SENSITIVE_ROWS or _SENSITIVE_OBJECT.search(obj):
                emit(
                    e,
                    "sensitive_db_access",
                    f"bulk/sensitive data read: {obj} ({rows} rows)",
                    "Collection",
                    "T1213",
                )


# --- windowed / stateful detectors ------------------------------------------------


def _detect_bruteforce(events, config: DetectionConfig, emit) -> None:
    window = timedelta(seconds=config.bruteforce_window_seconds)
    success_window = timedelta(seconds=config.success_after_failures_seconds)

    failures: dict[tuple, list[EventView]] = defaultdict(list)
    for e in events:
        if e.event_type == EventType.AUTHENTICATION and e.outcome == EventOutcome.FAILURE:
            failures[(e.host, e.source_ip)].append(e)

    burst_ends: dict[tuple, list[datetime]] = defaultdict(list)
    for key, group in failures.items():
        group.sort(key=lambda e: e.timestamp)
        flagged: dict = {}
        for i, anchor in enumerate(group):
            recent = [g for g in group[: i + 1] if anchor.timestamp - g.timestamp <= window]
            if len(recent) >= config.bruteforce_min_failures:
                flagged.update({g.id: g for g in recent})
                burst_ends[key].append(anchor.timestamp)
        for e in flagged.values():
            emit(
                e,
                "auth_bruteforce",
                f"{len(flagged)} failed logons for {key[1]} -> {key[0]}",
                "Credential Access",
                "T1110.001",
            )

    # Successful logon shortly after a brute-force burst from the same source.
    for e in events:
        if not (e.event_type == EventType.AUTHENTICATION and e.outcome == EventOutcome.SUCCESS):
            continue
        ends = burst_ends.get((e.host, e.source_ip), [])
        if any(timedelta(0) <= e.timestamp - end <= success_window for end in ends):
            emit(
                e,
                "auth_success_after_failures",
                f"successful logon for {e.username} after brute-force from {e.source_ip}",
                "Initial Access",
                "T1078",
            )


def _detect_portscan(events, config: DetectionConfig, emit) -> None:
    window = timedelta(seconds=config.portscan_window_seconds)
    by_source: dict[str, list[EventView]] = defaultdict(list)
    for e in events:
        if e.event_type == EventType.NETWORK and e.host and (e.dest_ip or e.dest_host):
            by_source[e.host].append(e)

    for host, group in by_source.items():
        group.sort(key=lambda e: e.timestamp)
        for i, anchor in enumerate(group):
            window_events = [
                g for g in group[max(0, i - 50) : i + 1] if anchor.timestamp - g.timestamp <= window
            ]
            targets = {(g.dest_ip or g.dest_host, g.dest_port) for g in window_events}
            if len(targets) >= config.portscan_min_targets:
                for g in window_events:
                    emit(
                        g,
                        "port_scan",
                        f"{host} probed {len(targets)} host:port pairs in a short window",
                        "Discovery",
                        "T1046",
                    )
                break


def _detect_first_seen_logon(baseline, live, emit) -> None:
    seen = {
        (e.source_ip, e.host, e.normalized_user)
        for e in baseline
        if e.event_type == EventType.AUTHENTICATION and e.protocol in _REMOTE_PROTOCOLS
    }
    for e in live:
        if (
            e.event_type == EventType.AUTHENTICATION
            and e.outcome == EventOutcome.SUCCESS
            and e.protocol in _REMOTE_PROTOCOLS
            and e.source_ip
        ):
            key = (e.source_ip, e.host, e.normalized_user)
            if key not in seen:
                emit(
                    e,
                    "first_seen_remote_logon",
                    f"first-ever {e.protocol} logon {e.source_ip} -> {e.host} as {e.username}",
                    "Lateral Movement",
                    "T1021",
                )


def _detect_service_account(baseline, live, emit) -> None:
    # Baseline process profile per service-looking account (svc_*, *$).
    def is_service(user: str | None) -> bool:
        return bool(user) and (user.lower().startswith("svc") or user.endswith("$"))

    profile: dict[str, set[str]] = defaultdict(set)
    for e in baseline:
        if e.event_type == EventType.PROCESS and is_service(e.username) and e.process:
            profile[e.username].add(e.process.lower())

    for e in live:
        if (
            e.event_type == EventType.PROCESS
            and is_service(e.username)
            and e.process
            and e.process.lower() not in profile.get(e.username, set())
        ):
            emit(
                e,
                "service_account_anomaly",
                f"service account {e.username} ran unusual process {e.process}",
                "Execution",
                "T1569",
            )


def _detect_suspicious_dns(baseline, live, result: DetectionResult, emit) -> None:
    known = {e.domain.lower() for e in baseline if e.domain}
    for e in live:
        if (
            e.event_type == EventType.DNS
            and e.domain
            and e.process  # process-attributed (Sysmon) query only
            and e.domain.lower() not in known
        ):
            emit(
                e,
                "suspicious_dns",
                f"novel domain queried by {e.process}: {e.domain}",
                "Command and Control",
                "T1071.001",
            )
