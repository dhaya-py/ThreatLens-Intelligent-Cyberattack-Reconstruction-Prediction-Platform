from datetime import UTC, datetime

import pytest

from app.models.enums import EventOutcome, EventType
from app.services.normalization import NormalizationError, normalize, supported_sources
from app.simulation.generator import generate_dataset


def test_all_simulation_sources_have_a_normalizer() -> None:
    sources = {e["source"] for e in generate_dataset().events}
    assert sources.issubset(set(supported_sources()))


def test_every_generated_event_normalizes_and_timestamp_matches_native_field() -> None:
    # Parsing the native per-source timestamp must agree with the generator's
    # own ts_utc — proving normalization reads the real fields, not a shortcut.
    for event in generate_dataset().events:
        norm = normalize(event)
        expected = datetime.fromisoformat(event["ts_utc"])
        assert norm.timestamp == expected, event["source"]
        assert norm.external_id == event["external_id"]


def test_windows_4624_remote_logon_is_a_connection() -> None:
    norm = normalize(
        {
            "source": "windows_security",
            "TimeCreated": "2026-03-14T10:10:05.000Z",
            "EventID": 4624,
            "Computer": "APP-01.corp.local",
            "TargetUserName": "svc_app",
            "TargetDomainName": "CORP",
            "LogonType": 3,
            "IpAddress": "10.10.1.10",
        }
    )
    assert norm.event_type == EventType.AUTHENTICATION
    assert norm.outcome == EventOutcome.SUCCESS
    assert norm.username == "svc_app"
    assert norm.hostname == "APP-01"
    assert norm.is_connection is True
    assert norm.destination_hostname == "APP-01"
    assert norm.protocol == "smb"
    assert norm.timestamp == datetime(2026, 3, 14, 10, 10, 5, tzinfo=UTC)


def test_windows_4625_failure() -> None:
    norm = normalize(
        {
            "source": "windows_security",
            "TimeCreated": "2026-03-14T09:52:00.000Z",
            "EventID": 4625,
            "Computer": "WEB-01.corp.local",
            "TargetUserName": "webadmin",
            "LogonType": 10,
            "IpAddress": "203.0.113.66",
        }
    )
    assert norm.outcome == EventOutcome.FAILURE
    assert norm.is_connection is False  # failed logons are not connections


def test_sysmon_process_strips_paths_and_domain() -> None:
    norm = normalize(
        {
            "source": "sysmon",
            "UtcTime": "2026-03-14 10:03:05.000",
            "EventID": 1,
            "Computer": "WEB-01.corp.local",
            "User": "CORP\\webadmin",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentImage": r"C:\Windows\explorer.exe",
            "CommandLine": "powershell.exe -enc AAAA",
            "ProcessId": 4820,
            "ParentProcessId": 3990,
        }
    )
    assert norm.process_name == "powershell.exe"
    assert norm.parent_process == "explorer.exe"
    assert norm.username == "webadmin"
    assert norm.event_type == EventType.PROCESS


def test_firewall_epoch_and_action_mapping() -> None:
    ts = datetime(2026, 3, 14, 10, 10, 4, tzinfo=UTC)
    norm = normalize(
        {
            "source": "firewall",
            "ts": ts.timestamp(),
            "src_ip": "10.10.1.10",
            "dst_ip": "10.10.2.20",
            "dst_port": 5985,
            "proto": "tcp",
            "action": "deny",
            "bytes_sent": 100,
        }
    )
    assert norm.timestamp == ts
    assert norm.outcome == EventOutcome.FAILURE
    assert norm.destination_port == 5985
    assert norm.is_connection is True


def test_mssql_seven_digit_fraction_and_database_type() -> None:
    norm = normalize(
        {
            "source": "mssql_audit",
            "event_time": "2026-03-14 10:13:02.0000000",
            "server_instance_name": "DB-01",
            "server_principal_name": "CORP\\svc_app",
            "client_ip": "10.10.2.20",
            "statement": "SELECT * FROM dbo.Customers",
            "object_name": "dbo.Customers",
            "affected_rows": 48213,
            "application_name": "sqlcmd",
        }
    )
    assert norm.event_type == EventType.DATABASE
    assert norm.timestamp == datetime(2026, 3, 14, 10, 13, 2, tzinfo=UTC)
    assert norm.destination_hostname == "DB-01"
    assert norm.metadata["affected_rows"] == 48213


def test_linux_auth_accepted_and_connection_lines() -> None:
    accepted = normalize(
        {
            "source": "linux_auth",
            "timestamp": "2026-03-13T01:30:01.000000+00:00",
            "hostname": "backup-01",
            "program": "sshd",
            "pid": 2201,
            "message": "Accepted publickey for svc_backup from 10.10.3.40 port 51002 ssh2",
        }
    )
    assert accepted.username == "svc_backup"
    assert accepted.source_ip == "10.10.3.40"
    assert accepted.hostname == "BACKUP-01"
    assert accepted.is_connection is True

    probe = normalize(
        {
            "source": "linux_auth",
            "timestamp": "2026-03-14T10:21:01.000000+00:00",
            "hostname": "backup-01",
            "program": "sshd",
            "pid": 4410,
            "message": "Connection from 10.10.3.40 port 52400 on 10.10.3.50 port 22",
        }
    )
    assert probe.event_type == EventType.NETWORK
    assert probe.source_ip == "10.10.3.40"


def test_csv_string_values_are_coerced() -> None:
    # CSV delivers every field as a string; normalizers must still work.
    norm = normalize(
        {
            "source": "firewall",
            "ts": "1773828604.0",
            "src_ip": "10.10.1.10",
            "dst_ip": "10.10.2.20",
            "dst_port": "5985",
            "action": "allow",
            "bytes_sent": "8200",
        }
    )
    assert norm.destination_port == 5985
    assert norm.bytes_sent == 8200


def test_unknown_source_raises() -> None:
    with pytest.raises(NormalizationError):
        normalize({"source": "carbon_black", "ts": 1})
    with pytest.raises(NormalizationError):
        normalize({"no_source": True})
