import pytest

from app.engines.correlation import correlate
from app.engines.lateral_movement import detect_lateral_movement
from app.engines.loader import from_raw_records
from app.engines.root_cause import detect_root_cause
from app.simulation.generator import generate_dataset


@pytest.fixture(scope="module")
def root_cause():
    views = from_raw_records(generate_dataset().events)
    result = correlate(views)
    incident = [e for e in views if e.id in set(result.clusters[0].event_ids)]
    movements = detect_lateral_movement(views, result.detection)
    return detect_root_cause(incident, result.detection, movements)


def test_identifies_web01_as_initial_entry(root_cause):
    assert root_cause.root_host == "WEB-01"
    assert root_cause.source_ip == "203.0.113.66"
    assert root_cause.first_seen.strftime("%H:%M") == "09:52"
    assert root_cause.confidence >= 0.8


def test_root_is_ranked_clearly_above_others(root_cause):
    assert root_cause.ranking[0].host == "WEB-01"
    assert root_cause.ranking[0].score > root_cause.ranking[1].score + 0.2


def test_explanation_is_descriptive(root_cause):
    text = root_cause.explanation
    assert "WEB-01" in text
    assert "203.0.113.66" in text
    assert "lateral movement" in text.lower()
    assert "APP-01" in text


def test_evidence_lists_the_contributing_factors(root_cause):
    joined = " ".join(root_cause.evidence).lower()
    assert "earliest" in joined
    assert "external ip" in joined
    assert "lateral movement" in joined


def test_no_signals_yields_empty_root_cause():
    dataset = generate_dataset()
    labels = dataset.ground_truth["labels"]
    benign = from_raw_records([e for e in dataset.events if e["external_id"] not in labels])
    result = detect_root_cause(benign)
    assert result.root_host is None
