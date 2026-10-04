import csv
import io
import json

from app.simulation.generator import INCIDENT_DATE, generate_dataset
from app.simulation.inventory import HOSTS_BY_NAME


def test_generation_is_deterministic() -> None:
    first = generate_dataset()
    second = generate_dataset()
    assert first.events == second.events
    assert first.ground_truth == second.ground_truth


def test_events_are_time_sorted_with_stable_ids() -> None:
    events = generate_dataset().events
    timestamps = [e["ts_utc"] for e in events]
    assert timestamps == sorted(timestamps)
    ids = [e["external_id"] for e in events]
    assert ids == [f"evt-{i:05d}" for i in range(1, len(events) + 1)]
    assert len(set(ids)) == len(ids)


def test_dataset_mixes_benign_and_malicious() -> None:
    dataset = generate_dataset()
    total = len(dataset.events)
    malicious = dataset.ground_truth["malicious_event_count"]
    # Benign activity should dominate so detection has to discriminate.
    assert malicious > 50
    assert total - malicious > total * 0.6


def test_ground_truth_labels_reference_real_events() -> None:
    dataset = generate_dataset()
    ids = {e["external_id"] for e in dataset.events}
    labels = dataset.ground_truth["labels"]
    assert set(labels).issubset(ids)
    assert set(labels.values()) == set(dataset.ground_truth["attack_step_order"])


def test_labels_are_not_present_in_ingestible_events() -> None:
    # The whole point: raw events must not carry the ground-truth answer.
    for event in generate_dataset().events:
        assert "label" not in event
        assert not any("label" in key.lower() for key in event)


def test_every_source_format_is_represented() -> None:
    sources = {e["source"] for e in generate_dataset().events}
    assert sources == {
        "windows_security",
        "sysmon",
        "firewall",
        "dns_server",
        "linux_auth",
        "mssql_audit",
    }


def test_attack_is_confined_to_incident_day() -> None:
    dataset = generate_dataset()
    by_id = {e["external_id"]: e for e in dataset.events}
    for ext_id in dataset.ground_truth["labels"]:
        day = by_id[ext_id]["ts_utc"][:10]
        assert day == INCIDENT_DATE.date().isoformat()


def test_initial_access_is_a_bruteforce_from_external_ip() -> None:
    dataset = generate_dataset()
    by_id = {e["external_id"]: e for e in dataset.events}
    failures = [
        by_id[i]
        for i, lbl in dataset.ground_truth["labels"].items()
        if lbl == "initial_access_bruteforce" and by_id[i].get("EventID") == 4625
    ]
    assert len(failures) >= 10
    web_fqdn = HOSTS_BY_NAME["WEB-01"].fqdn
    assert all(f["Computer"] == web_fqdn for f in failures)
    assert {f["IpAddress"] for f in failures} == {"203.0.113.66"}


def test_csv_roundtrips_and_matches_event_count() -> None:
    dataset = generate_dataset()
    rows = list(csv.DictReader(io.StringIO(dataset.events_csv())))
    assert len(rows) == len(dataset.events)
    assert rows[0]["external_id"] == "evt-00001"


def test_json_export_parses() -> None:
    dataset = generate_dataset()
    assert json.loads(dataset.events_json()) == dataset.events
