"""Correlation-stage tests, scored against ground truth."""

import pytest

from app.engines.correlation import correlate
from app.engines.loader import from_raw_records
from app.simulation.generator import generate_dataset

# Steps that should land in the reconstructed incident. The bare SSH probe of
# BACKUP-01 has no auth/content to correlate on; it is surfaced by the prediction
# engine (Phase 8), not required as an incident member here.
EXPECTED_STEPS = {
    "initial_access_bruteforce",
    "initial_access_success",
    "execution_powershell",
    "command_and_control",
    "credential_access_lsass",
    "discovery_account",
    "discovery_network",
    "lateral_movement_winrm",
    "remote_execution_app",
    "collection_database",
    "lateral_movement_smb",
    "credential_access_files",
}


@pytest.fixture(scope="module")
def dataset():
    return generate_dataset()


@pytest.fixture(scope="module")
def result(dataset):
    return correlate(from_raw_records(dataset.events))


def test_exactly_one_incident_is_reconstructed(result):
    # Benign look-alikes must not spawn extra incidents.
    assert len(result.clusters) == 1


def test_incident_is_precise(result, dataset):
    labels = dataset.ground_truth["labels"]
    cluster = result.clusters[0]
    malicious = [i for i in cluster.event_ids if i in labels]
    precision = len(malicious) / len(cluster.event_ids)
    assert precision >= 0.9, f"incident precision {precision:.2f}"


def test_incident_has_high_recall(result, dataset):
    labels = dataset.ground_truth["labels"]
    captured = {i for i in result.clusters[0].event_ids if i in labels}
    recall = len(captured) / len(labels)
    assert recall >= 0.85, f"incident recall {recall:.2f}"


def test_incident_covers_the_full_kill_chain(result, dataset):
    labels = dataset.ground_truth["labels"]
    captured_steps = {labels[i] for i in result.clusters[0].event_ids if i in labels}
    missing = EXPECTED_STEPS - captured_steps
    assert not missing, f"kill-chain steps missing from incident: {sorted(missing)}"


def test_incident_spans_multiple_hosts_and_families(result):
    cluster = result.clusters[0]
    assert len(cluster.detectors) >= 5
    # Members carry confidence and human-readable reasons for explainability.
    signal_members = [m for m in cluster.members if m.role == "signal"]
    assert all(0 < m.confidence <= 1 for m in signal_members)
    assert all(m.reasons for m in signal_members)


def test_context_expansion_pulls_in_benign_projections(result):
    cluster = result.clusters[0]
    roles = {m.role for m in cluster.members}
    assert "context" in roles  # e.g. the C2 DNS/network projection of a signal


def test_correlation_is_deterministic(dataset):
    a = correlate(from_raw_records(dataset.events))
    b = correlate(from_raw_records(dataset.events))
    assert [sorted(map(str, c.event_ids)) for c in a.clusters] == [
        sorted(map(str, c.event_ids)) for c in b.clusters
    ]


def test_purely_benign_data_yields_no_incident():
    # Strip the attack: only baseline + benign incident-day traffic remain.
    dataset = generate_dataset()
    labels = dataset.ground_truth["labels"]
    benign = [e for e in dataset.events if e["external_id"] not in labels]
    result = correlate(from_raw_records(benign))
    assert result.clusters == []
