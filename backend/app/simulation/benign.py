"""Benign background activity.

This is the noise the detection and correlation engines must see past. It
deliberately includes *look-alikes* of the malicious behaviour so that naive
rules ("any PowerShell", "any RDP", "any service-account SQL") would raise false
positives:

* `svc_app` runs normal APP-01 -> DB-01 SQL all day (same account the attacker
  reuses later), but from `java.exe`, not `sqlcmd.exe`.
* `it.admin` legitimately uses RDP from WS-IT-01 to APP-01/FILE-01.
* A signed, scheduled maintenance PowerShell script runs on APP-01 (no `-enc`).
* `svc_backup` runs the nightly FILE-01 -> BACKUP-01 SSH job.
"""

from datetime import datetime, timedelta
from random import Random

from app.simulation import records as r
from app.simulation.inventory import (
    DNS_SUFFIX,
    HOSTS_BY_NAME,
    SCANNER_NET,
    STAFF,
    WEB_CLIENT_NET,
    WORKSTATIONS,
)

SAAS_DOMAINS = (
    "outlook.office365.com",
    "teams.microsoft.com",
    "www.google.com",
    "api.github.com",
    "update.microsoft.com",
    "slack.com",
    "zoom.us",
    "cdn.jsdelivr.net",
)


def _at(day: datetime, hour: int, minute: int, second: int = 0) -> datetime:
    return day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def generate_benign(day: datetime, rng: Random) -> list[r.SimRecord]:
    """One business day of benign telemetry across the estate."""
    out: list[r.SimRecord] = []
    dc = HOSTS_BY_NAME["DC-01"]
    app = HOSTS_BY_NAME["APP-01"]
    db = HOSTS_BY_NAME["DB-01"]
    web = HOSTS_BY_NAME["WEB-01"]
    file = HOSTS_BY_NAME["FILE-01"]
    backup = HOSTS_BY_NAME["BACKUP-01"]
    pid = iter(range(1000, 1_000_000))

    # Morning: staff log on to their workstations and authenticate to the DC.
    for user in STAFF:
        ws = HOSTS_BY_NAME[user.workstation]
        login = _at(day, 8, rng.randint(0, 55), rng.randint(0, 59))
        # The occasional fat-fingered password (1-2 failures) is normal.
        for _ in range(rng.choice([0, 0, 0, 1, 2])):
            out.append(
                r.win_logon_failure(
                    login - timedelta(seconds=rng.randint(5, 40)), ws, user.username, 2, None
                )
            )
        out.append(r.win_logon(login, ws, user.username, 2, None, workstation=ws.hostname))
        out.append(r.win_logon(login + timedelta(seconds=2), dc, user.username, 3, ws.ip_address))

        # Scattered DNS lookups and web browsing through the day.
        for _ in range(rng.randint(4, 9)):
            t = _at(day, rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59))
            domain = rng.choice(SAAS_DOMAINS)
            answer = f"20.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            out.append(r.dns_query(t, ws.ip_address, domain, answer))
            out.append(
                r.firewall(
                    t + timedelta(seconds=1),
                    ws.ip_address,
                    answer,
                    443,
                    rng.randint(49152, 65535),
                    bytes_sent=rng.randint(2_000, 90_000),
                    rule="corp_web",
                )
            )

    # Finance staff reach the DB through the app, and open files on FILE-01.
    for user in (u for u in STAFF if u.department == "Finance"):
        ws = HOSTS_BY_NAME[user.workstation]
        for _ in range(rng.randint(2, 5)):
            t = _at(day, rng.randint(9, 16), rng.randint(0, 59), rng.randint(0, 59))
            out.append(
                r.firewall(
                    t,
                    ws.ip_address,
                    web.ip_address,
                    8080,
                    rng.randint(49152, 65535),
                    bytes_sent=rng.randint(1_000, 20_000),
                    rule="corp_app",
                )
            )
        for _ in range(rng.randint(1, 3)):
            t = _at(day, rng.randint(9, 16), rng.randint(0, 59), rng.randint(0, 59))
            out.append(
                r.win_share_access(
                    t,
                    file,
                    user.username,
                    ws.ip_address,
                    "finance$",
                    f"reports\\Q{rng.randint(1, 4)}_summary.xlsx",
                )
            )

    # Legitimate external visitors hitting the public web server.
    for _ in range(rng.randint(40, 70)):
        t = _at(day, rng.randint(7, 20), rng.randint(0, 59), rng.randint(0, 59))
        client = f"{WEB_CLIENT_NET}{rng.randint(1, 254)}"
        out.append(
            r.firewall(
                t,
                client,
                web.ip_address,
                443,
                rng.randint(1024, 65535),
                bytes_sent=rng.randint(500, 40_000),
                rule="web_inbound",
            )
        )

    # Background internet scan noise against the DMZ (blocked).
    for _ in range(rng.randint(8, 16)):
        t = _at(day, rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59))
        out.append(
            r.firewall(
                t,
                f"{SCANNER_NET}{rng.randint(1, 254)}",
                web.ip_address,
                rng.choice([22, 23, 3389, 8080]),
                rng.randint(1024, 65535),
                action="deny",
                rule="perimeter_drop",
            )
        )

    # WEB-01 app pool talks to APP-01 over HTTP all day (normal tier traffic).
    for _ in range(rng.randint(30, 50)):
        t = _at(day, rng.randint(7, 20), rng.randint(0, 59), rng.randint(0, 59))
        out.append(
            r.sysmon_network(
                t,
                web,
                "svc_web",
                r"C:\Windows\System32\inetsrv\w3wp.exe",
                app.ip_address,
                8080,
                rng.randint(49152, 65535),
                next(pid),
            )
        )

    # APP-01 -> DB-01 SQL as svc_app, from java.exe. Same account the attacker
    # reuses later, but a completely different, benign access pattern.
    for _ in range(rng.randint(40, 60)):
        t = _at(day, rng.randint(6, 21), rng.randint(0, 59), rng.randint(0, 59))
        out.append(
            r.mssql_audit(
                t,
                db,
                "svc_app",
                app.ip_address,
                "jdbc",
                "SELECT TOP 1 * FROM dbo.AppConfig WHERE Key=@k",
                "dbo.AppConfig",
                affected_rows=1,
            )
        )

    # Scheduled, signed maintenance PowerShell on APP-01 (no -enc, benign).
    maint = _at(day, 3, 15)
    out.append(
        r.sysmon_process(
            maint,
            app,
            "svc_app",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\taskeng.exe",
            r"powershell.exe -File C:\Scripts\Rotate-Logs.ps1",
            next(pid),
            640,
        )
    )

    # IT admin does afternoon maintenance over RDP (legitimate lateral-ish use).
    it_ws = HOSTS_BY_NAME["WS-IT-01"]
    for target in (app, file):
        t = _at(day, 14, rng.randint(0, 50), rng.randint(0, 59))
        out.append(r.win_logon(t, target, "it.admin", 10, it_ws.ip_address, workstation="WS-IT-01"))
        out.append(
            r.firewall(
                t - timedelta(seconds=1),
                it_ws.ip_address,
                target.ip_address,
                3389,
                rng.randint(49152, 65535),
                bytes_sent=rng.randint(5_000, 50_000),
                rule="it_admin",
            )
        )

    # Nightly backup job: FILE-01 -> BACKUP-01 over SSH as svc_backup. This is
    # why svc_backup credentials are exposed on FILE-01 (used by prediction).
    night = _at(day, 1, 30)
    out.append(
        r.firewall(
            night,
            file.ip_address,
            backup.ip_address,
            22,
            rng.randint(49152, 65535),
            bytes_sent=rng.randint(5_000_000, 40_000_000),
            rule="backup_job",
        )
    )
    out.append(
        r.linux_auth(
            night + timedelta(seconds=1),
            backup,
            "Accepted publickey for svc_backup from 10.10.3.40 port 51002 ssh2",
            2201,
        )
    )

    # Workstations fetch patches and run scheduled tasks.
    for ws in WORKSTATIONS:
        t = _at(day, rng.randint(2, 5), rng.randint(0, 59))
        out.append(
            r.sysmon_process(
                t,
                ws,
                "SYSTEM",
                r"C:\Windows\System32\svchost.exe",
                r"C:\Windows\System32\services.exe",
                r"svchost.exe -k netsvcs -p",
                next(pid),
                712,
            )
        )
        out.append(r.dns_query(t, ws.ip_address, f"wpad.{DNS_SUFFIX}", "-", rcode="NXDOMAIN"))

    return out
