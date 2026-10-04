import pytest

from app.engines.correlation import correlate
from app.engines.lateral_movement import detect_lateral_movement
from app.engines.loader import from_raw_records
from app.engines.mitre import TECHNIQUES, map_attack_steps, techniques_summary
from app.simulation.generator import generate_dataset


@pytest.fixture(scope="module")
def steps():
    views = from_raw_records(generate_dataset().events)
    result = correlate(views)
    incident = [e for e in views if e.id in set(result.clusters[0].event_ids)]
    movements = detect_lateral_movement(views, result.detection)
    return map_attack_steps(incident, result.detection, movements)


def test_timeline_is_chronological_and_sequenced(steps):
    assert [s.sequence for s in steps] == list(range(1, len(steps) + 1))
    assert steps == sorted(steps, key=lambda s: s.sequence)
    timestamps = [s.timestamp for s in steps]
    assert timestamps == sorted(timestamps)


def test_full_kill_chain_techniques_present(steps):
    ids = {s.technique_id for s in steps}
    expected = {
        "T1110.001",  # brute force
        "T1078",  # valid accounts (initial access)
        "T1059.001",  # powershell
        "T1071.001",  # C2
        "T1003.001",  # LSASS
        "T1087.002",  # account discovery
        "T1046",  # network discovery
        "T1021.006",  # WinRM lateral movement
        "T1021.002",  # SMB lateral movement
        "T1213",  # database collection
        "T1552.001",  # credentials in files
    }
    assert expected <= ids


def test_kill_chain_begins_with_initial_access_and_moves_laterally(steps):
    first = steps[0]
    assert first.tactic == "Credential Access"  # brute force precedes access
    assert first.technique_id == "T1110.001"
    # Initial Access (valid accounts) is the second beat, on the entry host.
    initial = next(s for s in steps if s.technique_id == "T1078")
    assert initial.host == "WEB-01"
    # Lateral movement reaches APP-01 then FILE-01, in order.
    lm = [s for s in steps if s.tactic == "Lateral Movement"]
    assert [s.host for s in lm] == ["APP-01", "FILE-01"]


def test_steps_are_explainable(steps):
    for s in steps:
        assert s.technique_id in TECHNIQUES
        assert s.technique_name == TECHNIQUES[s.technique_id][0]
        assert s.tactic == TECHNIQUES[s.technique_id][1]
        assert s.evidence and s.event_ids
        assert 0 < s.confidence <= 1


def test_no_duplicate_technique_per_host(steps):
    keys = [(s.technique_id, s.host) for s in steps]
    assert len(keys) == len(set(keys))


def test_database_collection_is_attributed_to_db01(steps):
    collection = next(s for s in steps if s.technique_id == "T1213")
    assert collection.host == "DB-01"
    assert collection.tactic == "Collection"


def test_techniques_summary_groups_hosts(steps):
    summary = techniques_summary(steps)
    powershell = next(t for t in summary if t["technique_id"] == "T1059.001")
    assert set(powershell["hosts"]) == {"WEB-01", "APP-01"}


def test_mapping_is_deterministic():
    views = from_raw_records(generate_dataset().events)
    result = correlate(views)
    incident = [e for e in views if e.id in set(result.clusters[0].event_ids)]
    movements = detect_lateral_movement(views, result.detection)
    a = map_attack_steps(incident, result.detection, movements)
    b = map_attack_steps(incident, result.detection, movements)
    assert [(s.technique_id, s.host, s.sequence) for s in a] == [
        (s.technique_id, s.host, s.sequence) for s in b
    ]
