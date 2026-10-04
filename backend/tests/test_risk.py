import pytest

from app.core.scoring import severity_for
from app.engines.correlation import correlate
from app.engines.lateral_movement import detect_lateral_movement
from app.engines.loader import from_raw_records
from app.engines.mitre import map_attack_steps
from app.engines.risk import compute_risk
from app.engines.root_cause import detect_root_cause
from app.models.enums import HostStatus
from app.simulation.generator import generate_dataset
from app.simulation.inventory import HOSTS

CRITICALITY = {h.hostname: h.criticality for h in HOSTS}


@pytest.fixture(scope="module")
def risk():
    views = from_raw_records(generate_dataset().events)
    result = correlate(views)
    incident = [e for e in views if e.id in set(result.clusters[0].event_ids)]
    movements = detect_lateral_movement(views, result.detection)
    steps = map_attack_steps(incident, result.detection, movements)
    root = detect_root_cause(incident, result.detection, movements)
    return compute_risk(incident, CRITICALITY, result.detection, movements, steps, root.root_host)


def test_incident_is_critical(risk):
    assert risk.score >= 80
    assert risk.severity == "critical"
    assert risk.score == min(100, risk.score)


def test_scores_are_bounded_and_equal_factor_sums(risk):
    for hr in risk.host_risks:
        assert 0 <= hr.score <= 100
        assert hr.score == min(100, sum(f.points for f in hr.factors))
        for factor in hr.factors:
            assert factor.points > 0
            assert factor.evidence


def test_key_hosts_present_with_expected_status(risk):
    by_host = {hr.host: hr for hr in risk.host_risks}
    assert by_host["WEB-01"].status == HostStatus.INITIAL_ENTRY
    assert by_host["APP-01"].status == HostStatus.COMPROMISED
    assert by_host["FILE-01"].status == HostStatus.COMPROMISED
    assert by_host["DB-01"].status == HostStatus.ACCESSED


def test_criticality_drives_db01_factor(risk):
    db = next(hr for hr in risk.host_risks if hr.host == "DB-01")
    crit = next(f for f in db.factors if f.name == "Asset criticality")
    assert crit.points == 25  # criticality 5 * 5
    assert any(f.name == "Sensitive data access" for f in db.factors)


def test_web01_shows_credential_access_and_unusual_auth(risk):
    web = next(hr for hr in risk.host_risks if hr.host == "WEB-01")
    names = {f.name for f in web.factors}
    assert "Credential access" in names
    assert "Unusual authentication" in names
    assert "Outbound lateral movement" in names


def test_severity_bands():
    assert severity_for(90) == "critical"
    assert severity_for(70) == "high"
    assert severity_for(50) == "medium"
    assert severity_for(10) == "low"


def test_benign_only_has_no_risk():
    dataset = generate_dataset()
    labels = dataset.ground_truth["labels"]
    benign = from_raw_records([e for e in dataset.events if e["external_id"] not in labels])
    result = compute_risk(benign, CRITICALITY)
    assert result.score == 0
    assert result.host_risks == []
