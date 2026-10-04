import pytest

from app.engines.correlation import correlate
from app.engines.lateral_movement import detect_lateral_movement
from app.engines.loader import from_raw_records
from app.engines.prediction import predict_next_target
from app.engines.root_cause import detect_root_cause
from app.simulation.generator import generate_dataset
from app.simulation.inventory import HOSTS

CRITICALITY = {h.hostname: h.criticality for h in HOSTS}


@pytest.fixture(scope="module")
def prediction():
    views = from_raw_records(generate_dataset().events)
    result = correlate(views)
    incident = [e for e in views if e.id in set(result.clusters[0].event_ids)]
    movements = detect_lateral_movement(views, result.detection)
    root = detect_root_cause(incident, result.detection, movements)
    compromised = {root.root_host: root.first_seen}
    for m in movements:
        compromised[m.destination_host] = m.timestamp
    return predict_next_target(views, compromised, CRITICALITY)


def test_backup01_is_the_likely_next_target(prediction):
    assert prediction.top.host == "BACKUP-01"
    assert prediction.top.score >= 80


def test_prediction_is_explained_by_data(prediction):
    joined = " ".join(prediction.top.reasons).lower()
    assert "file-01" in joined  # reachable/probed from the frontier
    assert "ssh" in joined
    assert "svc_backup" in joined  # exposed credentials
    assert "criticality 5" in joined


def test_all_five_components_contribute_for_backup(prediction):
    comp = prediction.top.components
    assert comp["reachability"] > 0
    assert comp["credential_exposure"] == 1.0
    assert comp["criticality"] == 1.0
    assert comp["recent_probe"] == 1.0
    assert comp["chain_proximity"] == 1.0


def test_compromised_hosts_are_not_candidates(prediction):
    hosts = {t.host for t in prediction.ranking}
    assert "WEB-01" not in hosts
    assert "FILE-01" not in hosts


def test_ranking_is_ordered_and_backup_leads(prediction):
    scores = [t.score for t in prediction.ranking]
    assert scores == sorted(scores, reverse=True)
    assert prediction.ranking[0].host == "BACKUP-01"
    assert prediction.ranking[0].score > prediction.ranking[1].score


def test_ranks_are_assigned(prediction):
    assert [t.rank for t in prediction.ranking] == list(range(1, len(prediction.ranking) + 1))


def test_no_compromised_hosts_yields_no_prediction():
    views = from_raw_records(generate_dataset().events)
    result = predict_next_target(views, {}, CRITICALITY)
    assert result.top is None
    assert result.ranking == []
