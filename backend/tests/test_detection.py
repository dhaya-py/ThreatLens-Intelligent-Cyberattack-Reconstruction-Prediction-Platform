"""Detection-stage tests, scored against the generator's ground truth."""

import pytest

from app.engines.detection import detect
from app.engines.loader import from_raw_records
from app.simulation.generator import generate_dataset


@pytest.fixture(scope="module")
def dataset():
    return generate_dataset()


@pytest.fixture(scope="module")
def detection(dataset):
    views = from_raw_records(dataset.events)
    return detect(views)


@pytest.fixture(scope="module")
def labels(dataset):
    return dataset.ground_truth["labels"]  # external_id -> attack step


def test_signal_events_are_overwhelmingly_malicious(detection, labels):
    signal_ids = detection.signal_event_ids(0.4)
    malicious = sum(1 for sid in signal_ids if sid in labels)
    precision = malicious / len(signal_ids)
    # Benign look-alikes must not flood the signal set.
    assert precision >= 0.9, f"signal precision {precision:.2f} ({len(signal_ids)} signals)"


def test_core_attack_techniques_each_fire(detection, labels):
    # Each key stage of the attack should produce at least one signal.
    by_step_detectors: dict[str, set[str]] = {}
    for sid, dets in ((s, detection.detectors_for(s)) for s in detection.signal_event_ids(0.4)):
        step = labels.get(sid)
        if step:
            by_step_detectors.setdefault(step, set()).update(dets)

    assert "auth_bruteforce" in by_step_detectors.get("initial_access_bruteforce", set())
    assert "encoded_powershell" in by_step_detectors.get("execution_powershell", set())
    assert "lsass_access" in by_step_detectors.get("credential_access_lsass", set())
    assert "recon_commands" in by_step_detectors.get("discovery_account", set())
    assert "port_scan" in by_step_detectors.get("discovery_network", set())
    assert "first_seen_remote_logon" in by_step_detectors.get("lateral_movement_winrm", set())
    assert "service_account_anomaly" in by_step_detectors.get("collection_database", set())
    assert "admin_share_access" in by_step_detectors.get("lateral_movement_smb", set())
    assert "credential_file_access" in by_step_detectors.get("credential_access_files", set())
    assert "suspicious_dns" in by_step_detectors.get("command_and_control", set())


def test_benign_powershell_and_rdp_are_not_flagged(detection, dataset):
    # The scheduled Rotate-Logs PowerShell and it.admin RDP are benign look-alikes.
    by_id = {e["external_id"]: e for e in dataset.events}
    for sid in detection.signal_event_ids(0.4):
        raw = by_id.get(sid, {})
        assert "Rotate-Logs" not in (raw.get("CommandLine") or "")
        # it.admin interactive RDP from WS-IT-01 must not be a signal.
        if raw.get("TargetUserName") == "it.admin":
            raise AssertionError("benign it.admin RDP was flagged as a signal")


def test_bruteforce_requires_threshold(detection, labels):
    # All brute-force failures are malicious; ensure a healthy number were caught.
    caught = [
        sid
        for sid in detection.signal_event_ids(0.4)
        if "auth_bruteforce" in detection.detectors_for(sid)
    ]
    assert len(caught) >= 10
