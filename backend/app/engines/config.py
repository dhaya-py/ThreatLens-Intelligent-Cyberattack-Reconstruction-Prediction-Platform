"""Tunable parameters for the detection and correlation engines.

Defaults are deliberately generic (not fitted to the demo scenario). Benign
look-alikes in the dataset keep these honest: thresholds loose enough to miss the
attack would also flag normal admin activity, which the tests catch.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DetectionConfig:
    # auth_bruteforce
    bruteforce_min_failures: int = 10
    bruteforce_window_seconds: int = 600
    # auth_success_after_failures: success within this window of a brute-force burst
    success_after_failures_seconds: int = 900
    # port_scan
    portscan_min_targets: int = 8
    portscan_window_seconds: int = 120
    # suspicion threshold: events at or above this become "signal events"
    signal_threshold: float = 0.4

    # Per-detector base scores.
    scores: dict[str, float] = field(
        default_factory=lambda: {
            "auth_bruteforce": 0.80,
            "auth_success_after_failures": 0.90,
            "external_auth": 0.85,
            "encoded_powershell": 0.85,
            "lsass_access": 0.90,
            "recon_commands": 0.70,
            "port_scan": 0.75,
            "first_seen_remote_logon": 0.55,
            "remote_exec_parent": 0.80,
            "service_account_anomaly": 0.65,
            "service_execution": 0.65,
            "admin_share_access": 0.70,
            "credential_file_access": 0.70,
            "suspicious_dns": 0.50,
            "sensitive_db_access": 0.65,
        }
    )


@dataclass(frozen=True)
class CorrelationConfig:
    window_seconds: int = 2700  # 45 min pairwise window
    decay_tau_seconds: float = 1800.0  # 30 min exponential decay
    link_threshold: float = 0.35
    min_signal_events: int = 3
    min_detector_families: int = 2
    context_window_seconds: int = 60

    feature_weights: dict[str, float] = field(
        default_factory=lambda: {
            "same_host": 0.35,
            "pivot": 0.45,
            "same_user": 0.25,
            "same_source_ip": 0.25,
            "process_lineage": 0.30,
            "credential_flow": 0.30,
        }
    )


DEFAULT_DETECTION = DetectionConfig()
DEFAULT_CORRELATION = CorrelationConfig()
