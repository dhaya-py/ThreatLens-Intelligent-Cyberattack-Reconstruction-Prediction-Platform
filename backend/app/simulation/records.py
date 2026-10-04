"""Builders for raw telemetry records, one per log source.

Each source keeps its native field names and timestamp format so the
normalization layer (Phase 3) has to do real work:

| source            | timestamp field | format                         |
|-------------------|-----------------|--------------------------------|
| windows_security  | TimeCreated     | ISO 8601, `Z` suffix           |
| sysmon            | UtcTime         | `YYYY-MM-DD HH:MM:SS.mmm`      |
| firewall          | ts              | epoch seconds (float)          |
| dns_server        | timestamp       | ISO 8601 with offset           |
| linux_auth        | timestamp       | RFC 3339, microseconds         |
| mssql_audit       | event_time      | `YYYY-MM-DD HH:MM:SS.fffffff`  |
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.simulation.inventory import DOMAIN, SimHost


@dataclass
class SimRecord:
    """A raw record plus generator-side bookkeeping that is never exported."""

    ts: datetime
    data: dict[str, Any]
    # Ground-truth label (attack step key) or None for benign activity.
    label: str | None = None
    sort_key: tuple = field(default=())


def _account(username: str) -> str:
    return f"{DOMAIN}\\{username}"


def _iso_z(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _sysmon_time(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}"


# --- Windows Security log -------------------------------------------------------


def win_logon(
    ts: datetime,
    host: SimHost,
    username: str,
    logon_type: int,
    source_ip: str | None,
    workstation: str | None = None,
    auth_package: str = "Kerberos",
) -> SimRecord:
    """Event 4624 - an account was successfully logged on."""
    return SimRecord(
        ts,
        {
            "source": "windows_security",
            "TimeCreated": _iso_z(ts),
            "EventID": 4624,
            "Computer": host.fqdn,
            "TargetUserName": username,
            "TargetDomainName": DOMAIN,
            "LogonType": logon_type,
            "IpAddress": source_ip or "-",
            "WorkstationName": workstation or "-",
            "AuthenticationPackageName": auth_package,
        },
    )


def win_logon_failure(
    ts: datetime,
    host: SimHost,
    username: str,
    logon_type: int,
    source_ip: str | None,
    workstation: str | None = None,
) -> SimRecord:
    """Event 4625 - an account failed to log on (bad password)."""
    return SimRecord(
        ts,
        {
            "source": "windows_security",
            "TimeCreated": _iso_z(ts),
            "EventID": 4625,
            "Computer": host.fqdn,
            "TargetUserName": username,
            "TargetDomainName": DOMAIN,
            "LogonType": logon_type,
            "IpAddress": source_ip or "-",
            "WorkstationName": workstation or "-",
            "Status": "0xC000006D",
            "SubStatus": "0xC000006A",
        },
    )


def win_share_access(
    ts: datetime,
    host: SimHost,
    username: str,
    source_ip: str,
    share: str,
    relative_target: str,
    access: str = "ReadData",
) -> SimRecord:
    """Event 5145 - a network share object was checked for access."""
    return SimRecord(
        ts,
        {
            "source": "windows_security",
            "TimeCreated": _iso_z(ts),
            "EventID": 5145,
            "Computer": host.fqdn,
            "SubjectUserName": username,
            "SubjectDomainName": DOMAIN,
            "IpAddress": source_ip,
            "ShareName": f"\\\\*\\{share}",
            "RelativeTargetName": relative_target,
            "AccessList": access,
        },
    )


# --- Sysmon -----------------------------------------------------------------------


def sysmon_process(
    ts: datetime,
    host: SimHost,
    username: str,
    image: str,
    parent_image: str,
    command_line: str,
    pid: int,
    ppid: int,
) -> SimRecord:
    """Sysmon event 1 - process creation."""
    return SimRecord(
        ts,
        {
            "source": "sysmon",
            "UtcTime": _sysmon_time(ts),
            "EventID": 1,
            "Computer": host.fqdn,
            "User": _account(username) if "\\" not in username else username,
            "Image": image,
            "ParentImage": parent_image,
            "CommandLine": command_line,
            "ProcessId": pid,
            "ParentProcessId": ppid,
        },
    )


def sysmon_network(
    ts: datetime,
    host: SimHost,
    username: str,
    image: str,
    destination_ip: str,
    destination_port: int,
    source_port: int,
    pid: int,
) -> SimRecord:
    """Sysmon event 3 - network connection initiated."""
    return SimRecord(
        ts,
        {
            "source": "sysmon",
            "UtcTime": _sysmon_time(ts),
            "EventID": 3,
            "Computer": host.fqdn,
            "User": _account(username) if "\\" not in username else username,
            "Image": image,
            "ProcessId": pid,
            "Protocol": "tcp",
            "Initiated": True,
            "SourceIp": host.ip_address,
            "SourcePort": source_port,
            "DestinationIp": destination_ip,
            "DestinationPort": destination_port,
        },
    )


def sysmon_dns(
    ts: datetime, host: SimHost, username: str, image: str, query: str, result: str, pid: int
) -> SimRecord:
    """Sysmon event 22 - DNS query made by a process."""
    return SimRecord(
        ts,
        {
            "source": "sysmon",
            "UtcTime": _sysmon_time(ts),
            "EventID": 22,
            "Computer": host.fqdn,
            "User": _account(username) if "\\" not in username else username,
            "Image": image,
            "ProcessId": pid,
            "QueryName": query,
            "QueryResults": result,
        },
    )


def sysmon_process_access(
    ts: datetime,
    host: SimHost,
    username: str,
    source_image: str,
    target_image: str,
    granted_access: str,
    pid: int,
) -> SimRecord:
    """Sysmon event 10 - one process opened a handle to another."""
    return SimRecord(
        ts,
        {
            "source": "sysmon",
            "UtcTime": _sysmon_time(ts),
            "EventID": 10,
            "Computer": host.fqdn,
            "SourceUser": _account(username),
            "SourceImage": source_image,
            "SourceProcessId": pid,
            "TargetImage": target_image,
            "GrantedAccess": granted_access,
        },
    )


# --- Network & infrastructure logs ------------------------------------------------


def firewall(
    ts: datetime,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    src_port: int,
    action: str = "allow",
    bytes_sent: int = 0,
    rule: str = "default",
) -> SimRecord:
    """Perimeter / zone firewall connection log (Zeek-like flat record)."""
    return SimRecord(
        ts,
        {
            "source": "firewall",
            "ts": round(ts.timestamp(), 3),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": "tcp",
            "action": action,
            "bytes_sent": bytes_sent,
            "rule": rule,
        },
    )


def dns_query(ts: datetime, client_ip: str, query: str, answer: str, rcode: str = "NOERROR"):
    """DNS server query log."""
    return SimRecord(
        ts,
        {
            "source": "dns_server",
            "timestamp": ts.isoformat(timespec="milliseconds"),
            "client_ip": client_ip,
            "query": query,
            "qtype": "A",
            "rcode": rcode,
            "answer": answer,
        },
    )


def linux_auth(ts: datetime, host: SimHost, message: str, pid: int) -> SimRecord:
    """sshd syslog line from a Linux host."""
    return SimRecord(
        ts,
        {
            "source": "linux_auth",
            "timestamp": ts.isoformat(timespec="microseconds"),
            "hostname": host.hostname.lower(),
            "program": "sshd",
            "pid": pid,
            "message": message,
        },
    )


def mssql_audit(
    ts: datetime,
    server: SimHost,
    username: str,
    client_ip: str,
    application: str,
    statement: str,
    object_name: str,
    affected_rows: int,
) -> SimRecord:
    """SQL Server audit record (SELECT action)."""
    return SimRecord(
        ts,
        {
            "source": "mssql_audit",
            "event_time": ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond:06d}0",
            "server_instance_name": server.hostname,
            "action_id": "SL",
            "server_principal_name": _account(username),
            "client_ip": client_ip,
            "application_name": application,
            "database_name": "SalesDB",
            "object_name": object_name,
            "statement": statement,
            "affected_rows": affected_rows,
        },
    )
