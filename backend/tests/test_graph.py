import pytest

from app.engines.correlation import correlate
from app.engines.graph import build_graph, host_key
from app.engines.lateral_movement import detect_lateral_movement
from app.engines.loader import from_raw_records
from app.simulation.generator import generate_dataset


@pytest.fixture(scope="module")
def graph():
    views = from_raw_records(generate_dataset().events)
    result = correlate(views)
    incident = [e for e in views if e.id in set(result.clusters[0].event_ids)]
    movements = detect_lateral_movement(views, result.detection)
    signal_ids = result.detection.signal_event_ids(0.4)
    return build_graph(incident, movements, signal_ids=signal_ids)


def _nodes_of(graph, type_):
    return {n.label for n in graph.nodes if n.type == type_}


def test_graph_has_all_node_types(graph):
    for t in ("host", "user", "ip", "process", "domain"):
        assert _nodes_of(graph, t), f"no {t} nodes"


def test_key_entities_present(graph):
    assert {"WEB-01", "APP-01", "FILE-01"} <= _nodes_of(graph, "host")
    assert "203.0.113.66" in _nodes_of(graph, "ip")
    assert "update.cdn-sync.example" in _nodes_of(graph, "domain")
    assert "svc_app" in _nodes_of(graph, "user")


def test_external_ip_is_flagged(graph):
    attacker = next(n for n in graph.nodes if n.type == "ip" and n.label == "203.0.113.66")
    assert attacker.attributes.get("external") is True


def test_relationship_types_present(graph):
    rels = {e.relationship for e in graph.edges}
    assert {"AUTHENTICATED_TO", "SPAWNED", "CONNECTED_TO", "RESOLVED", "MOVED_TO"} <= rels


def test_moved_to_overlay_matches_movements(graph):
    moved = {
        (e.source, e.destination, e.protocol) for e in graph.edges if e.relationship == "MOVED_TO"
    }
    assert (host_key("WEB-01"), host_key("APP-01"), "winrm") in moved
    assert (host_key("APP-01"), host_key("FILE-01"), "smb") in moved


def test_initial_access_edge_from_external_ip(graph):
    auth = [
        e
        for e in graph.edges
        if e.relationship == "AUTHENTICATED_TO" and e.source == "ip:203.0.113.66"
    ]
    assert auth and auth[0].destination == host_key("WEB-01")


def test_edges_carry_evidence_and_no_self_loops(graph):
    for e in graph.edges:
        assert e.source != e.destination
        assert e.evidence
        assert e.event_ids
        assert 0 < e.confidence <= 1


def test_no_orphan_nodes(graph):
    referenced = {e.source for e in graph.edges} | {e.destination for e in graph.edges}
    assert all(n.key in referenced for n in graph.nodes)


def test_graph_is_deterministic():
    views = from_raw_records(generate_dataset().events)
    result = correlate(views)
    incident = [e for e in views if e.id in set(result.clusters[0].event_ids)]
    movements = detect_lateral_movement(views, result.detection)
    a = build_graph(incident, movements)
    b = build_graph(incident, movements)
    assert {n.key for n in a.nodes} == {n.key for n in b.nodes}
    assert {(e.source, e.destination, e.relationship) for e in a.edges} == {
        (e.source, e.destination, e.relationship) for e in b.edges
    }
