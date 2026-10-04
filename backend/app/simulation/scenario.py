"""The deterministic multi-stage attack, rendered as the telemetry a SOC sees.

Important: this produces *log records only*. There are no working payloads. The
"encoded PowerShell" argument is base64 of a harmless `Write-Output` string, so
the data exercises detection logic without carrying anything executable.

Each record is labelled with its attack-step key (ground truth). Labels are used
only by tests and by the generator's ground-truth export; they are never ingested.
"""

import base64
from datetime import datetime, timedelta

from app.simulation import records as r
from app.simulation.inventory import (
    ATTACKER_IP,
    C2_DOMAIN,
    C2_IP,
    HOSTS_BY_NAME,
)

# Inert: decodes to a harmless string, present only so encoded-command detection
# has a realistic-looking argument to match on.
_INERT_ENCODED = base64.b64encode("Write-Output 'threatlens-demo'".encode("utf-16-le")).decode()


def generate_scenario(day: datetime) -> list[r.SimRecord]:
    """The malicious chain on the incident day. Times are deterministic."""
    web = HOSTS_BY_NAME["WEB-01"]
    app = HOSTS_BY_NAME["APP-01"]
    db = HOSTS_BY_NAME["DB-01"]
    file = HOSTS_BY_NAME["FILE-01"]
    backup = HOSTS_BY_NAME["BACKUP-01"]

    def t(hour: int, minute: int, second: int = 0, micro: int = 0) -> datetime:
        return day.replace(hour=hour, minute=minute, second=second, microsecond=micro)

    out: list[r.SimRecord] = []

    def add(rec: r.SimRecord, label: str) -> r.SimRecord:
        rec.label = label
        out.append(rec)
        return rec

    # 1. Initial access: RDP brute force against WEB-01 from an external IP,
    #    then a successful logon for `webadmin`.
    for i in range(42):
        add(
            r.win_logon_failure(
                t(9, 52, 0) + timedelta(seconds=i * 12),
                web,
                "webadmin",
                10,
                ATTACKER_IP,
                workstation="KALI",
            ),
            "initial_access_bruteforce",
        )
    add(
        r.firewall(
            t(9, 51, 50),
            ATTACKER_IP,
            web.ip_address,
            3389,
            51000,
            bytes_sent=1200,
            rule="web_inbound",
        ),
        "initial_access_bruteforce",
    )
    add(
        r.win_logon(t(10, 1, 3), web, "webadmin", 10, ATTACKER_IP, workstation="KALI"),
        "initial_access_success",
    )

    # 2. Execution: explorer spawns an encoded, hidden PowerShell.
    add(
        r.sysmon_process(
            t(10, 3, 5),
            web,
            "webadmin",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\explorer.exe",
            f"powershell.exe -nop -w hidden -enc {_INERT_ENCODED}",
            4820,
            3990,
        ),
        "execution_powershell",
    )

    # 3. C2: beacon DNS lookup, then outbound HTTPS to the attacker host.
    add(
        r.sysmon_dns(
            t(10, 3, 20),
            web,
            "webadmin",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            C2_DOMAIN,
            C2_IP,
            4820,
        ),
        "command_and_control",
    )
    add(r.dns_query(t(10, 3, 20), web.ip_address, C2_DOMAIN, C2_IP), "command_and_control")
    add(
        r.sysmon_network(
            t(10, 3, 22),
            web,
            "webadmin",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            C2_IP,
            443,
            51333,
            4820,
        ),
        "command_and_control",
    )

    # 4. Credential access: LSASS memory dumped via comsvcs.dll MiniDump.
    add(
        r.sysmon_process(
            t(10, 5, 10),
            web,
            "webadmin",
            r"C:\Windows\System32\rundll32.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 "
            r"C:\Windows\Temp\lsass.dmp full",
            5120,
            4820,
        ),
        "credential_access_lsass",
    )
    add(
        r.sysmon_process_access(
            t(10, 5, 11),
            web,
            "webadmin",
            r"C:\Windows\System32\rundll32.exe",
            r"C:\Windows\System32\lsass.exe",
            "0x1010",
            5120,
        ),
        "credential_access_lsass",
    )

    # 5. Discovery: domain account/group enumeration.
    for cmd in (
        "net user /domain",
        'net group "Domain Admins" /domain',
        "nltest /dclist:corp",
    ):
        add(
            r.sysmon_process(
                t(10, 8, 0) + timedelta(seconds=7 * len(out) % 30),
                web,
                "webadmin",
                r"C:\Windows\System32\net.exe"
                if cmd.startswith("net")
                else r"C:\Windows\System32\nltest.exe",
                r"C:\Windows\System32\cmd.exe",
                cmd,
                5200 + len(out),
                4820,
            ),
            "discovery_account",
        )

    # 6. Network discovery: WEB-01 sweeps the app/data subnets on admin ports.
    scan_targets = [
        (app.ip_address, 445),
        (app.ip_address, 5985),
        (app.ip_address, 3389),
        (db.ip_address, 1433),
        (db.ip_address, 445),
        (file.ip_address, 445),
        (file.ip_address, 3389),
        (backup.ip_address, 22),
        (backup.ip_address, 445),
    ]
    for i, (dst, port) in enumerate(scan_targets):
        add(
            r.sysmon_network(
                t(10, 9, 0) + timedelta(seconds=i * 2),
                web,
                "webadmin",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                dst,
                port,
                52000 + i,
                4820,
            ),
            "discovery_network",
        )

    # 7. Lateral movement: WEB-01 -> APP-01 over WinRM using reused svc_app creds.
    add(
        r.firewall(
            t(10, 10, 4),
            web.ip_address,
            app.ip_address,
            5985,
            52100,
            bytes_sent=8200,
            rule="app_zone",
        ),
        "lateral_movement_winrm",
    )
    add(
        r.win_logon(
            t(10, 10, 5),
            app,
            "svc_app",
            3,
            web.ip_address,
            workstation="WEB-01",
            auth_package="NTLM",
        ),
        "lateral_movement_winrm",
    )

    # 8. Remote execution on APP-01: wsmprovhost spawns PowerShell.
    add(
        r.sysmon_process(
            t(10, 11, 2),
            app,
            "svc_app",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\wsmprovhost.exe",
            "powershell.exe -nop -w hidden -c IEX $env:a",
            6300,
            980,
        ),
        "remote_execution_app",
    )

    # 9. Collection: APP-01 -> DB-01 bulk SELECT via sqlcmd (svc_app anomaly).
    add(
        r.firewall(
            t(10, 13, 0),
            app.ip_address,
            db.ip_address,
            1433,
            52210,
            bytes_sent=25600,
            rule="data_zone",
        ),
        "collection_database",
    )
    add(
        r.sysmon_process(
            t(10, 13, 1),
            app,
            "svc_app",
            r"C:\Windows\System32\sqlcmd.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            'sqlcmd.exe -S DB-01 -Q "SELECT * FROM dbo.Customers"',
            6400,
            6300,
        ),
        "collection_database",
    )
    add(
        r.mssql_audit(
            t(10, 13, 2),
            db,
            "svc_app",
            app.ip_address,
            "sqlcmd",
            "SELECT * FROM dbo.Customers; SELECT * FROM dbo.CardData",
            "dbo.Customers",
            affected_rows=48213,
        ),
        "collection_database",
    )

    # 10. Lateral movement: APP-01 -> FILE-01 over SMB admin share + service exec.
    add(
        r.firewall(
            t(10, 16, 0),
            app.ip_address,
            file.ip_address,
            445,
            52300,
            bytes_sent=14300,
            rule="data_zone",
        ),
        "lateral_movement_smb",
    )
    add(
        r.win_logon(
            t(10, 16, 1),
            file,
            "svc_app",
            3,
            app.ip_address,
            workstation="APP-01",
            auth_package="NTLM",
        ),
        "lateral_movement_smb",
    )
    add(
        r.win_share_access(
            t(10, 16, 2),
            file,
            "svc_app",
            app.ip_address,
            "ADMIN$",
            "PSEXESVC.exe",
            access="WriteData",
        ),
        "lateral_movement_smb",
    )
    add(
        r.sysmon_process(
            t(10, 16, 4),
            file,
            "svc_app",
            r"C:\Windows\PSEXESVC.exe",
            r"C:\Windows\System32\services.exe",
            r"C:\Windows\PSEXESVC.exe",
            7100,
            640,
        ),
        "lateral_movement_smb",
    )

    # 11. Credential access: reads a backup config holding svc_backup secrets.
    add(
        r.win_share_access(
            t(10, 18, 0),
            file,
            "svc_app",
            app.ip_address,
            "it$",
            "scripts\\backup_config.xml",
            access="ReadData",
        ),
        "credential_access_files",
    )

    # 12. Discovery/probe toward BACKUP-01 (SSH), the likely next hop.
    add(
        r.firewall(
            t(10, 21, 0),
            file.ip_address,
            backup.ip_address,
            22,
            52400,
            action="allow",
            bytes_sent=320,
            rule="data_zone",
        ),
        "probe_backup",
    )
    add(
        r.linux_auth(
            t(10, 21, 1),
            backup,
            "Connection from 10.10.3.40 port 52400 on 10.10.3.50 port 22",
            4410,
        ),
        "probe_backup",
    )

    return out
