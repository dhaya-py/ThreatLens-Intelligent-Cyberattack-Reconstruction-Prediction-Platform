import pytest

from app.engines.correlation import correlate
from app.engines.lateral_movement import detect_lateral_movement
from app.engines.loader import from_raw_records
from app.simulation.generator import generate_dataset


@pytest.fixture(scope="module")
def views():
    return from_raw_records(generate_dataset().events)


@pytest.fixture(scope="module")
def movements(views):
    detection = correlate(views).detection
    return detect_lateral_movement(views, detection)


def test_detects_the_two_confirmed_hops(movements):
    hops = {(m.source_host, m.destination_host, m.protocol) for m in movements}
    assert ("WEB-01", "APP-01", "winrm") in hops
    assert ("APP-01", "FILE-01", "smb") in hops


def test_does_not_flag_data_access_or_probes(movements):
    pairs = {(m.source_host, m.destination_host) for m in movements}
    # SQL collection APP-01 -> DB-01 is not a host hop.
    assert ("APP-01", "DB-01") not in pairs
    # The unanswered SSH probe to BACKUP-01 is not a confirmed movement.
    assert ("FILE-01", "BACKUP-01") not in pairs


def test_does_not_flag_benign_admin_rdp(movements):
    # it.admin's RDP from an uncompromised workstation must not be a movement.
    pairs = {(m.source_host, m.destination_host) for m in movements}
    assert ("WS-IT-01", "APP-01") not in pairs
    assert ("WS-IT-01", "FILE-01") not in pairs


def test_movements_are_explainable_and_ordered(movements):
    assert movements == sorted(movements, key=lambda m: m.timestamp)
    for m in movements:
        assert 0 < m.confidence <= 1
        assert m.reason and m.evidence
        assert m.event_ids
        assert m.username == "svc_app"  # reused service-account credentials


def test_high_confidence_with_execution_and_first_seen(movements):
    web_app = next(m for m in movements if m.source_host == "WEB-01")
    assert web_app.confidence >= 0.85
    assert "remote execution" in web_app.reason


def test_benign_only_data_has_no_movements():
    dataset = generate_dataset()
    labels = dataset.ground_truth["labels"]
    benign = [e for e in dataset.events if e["external_id"] not in labels]
    views = from_raw_records(benign)
    assert detect_lateral_movement(views) == []
