"""The synthetic demo network: hosts, identities and fixed external addresses.

All external addresses come from documentation ranges (RFC 5737) and the C2
domain uses the reserved `.example` TLD, so nothing points at real infrastructure.
"""

from dataclasses import asdict, dataclass

DOMAIN = "CORP"
DNS_SUFFIX = "corp.local"


@dataclass(frozen=True)
class SimHost:
    hostname: str
    ip_address: str
    operating_system: str
    department: str
    criticality: int
    role: str
    network_zone: str

    @property
    def fqdn(self) -> str:
        return f"{self.hostname}.{DNS_SUFFIX}"

    @property
    def is_windows(self) -> bool:
        return self.operating_system.startswith("Windows")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class SimUser:
    username: str
    display_name: str
    department: str
    privilege_level: str
    is_service_account: bool = False
    workstation: str | None = None  # primary workstation for staff accounts

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("workstation")
        return data


HOSTS: tuple[SimHost, ...] = (
    SimHost("DC-01", "10.10.0.5", "Windows Server 2022", "IT", 5, "domain_controller", "infra"),
    SimHost("WEB-01", "10.10.1.10", "Windows Server 2019", "Digital", 3, "web_server", "dmz"),
    SimHost("APP-01", "10.10.2.20", "Windows Server 2022", "Engineering", 4, "app_server", "app"),
    SimHost("DB-01", "10.10.3.30", "Windows Server 2022", "Finance", 5, "database", "data"),
    SimHost("FILE-01", "10.10.3.40", "Windows Server 2019", "Operations", 4, "file_server", "data"),
    SimHost("BACKUP-01", "10.10.3.50", "Ubuntu 22.04 LTS", "IT", 5, "backup_server", "data"),
    SimHost(
        "WS-FIN-01", "10.10.10.11", "Windows 11 Enterprise", "Finance", 2, "workstation", "corp"
    ),
    SimHost(
        "WS-FIN-02", "10.10.10.12", "Windows 11 Enterprise", "Finance", 2, "workstation", "corp"
    ),
    SimHost("WS-HR-01", "10.10.10.21", "Windows 11 Enterprise", "HR", 2, "workstation", "corp"),
    SimHost("WS-HR-02", "10.10.10.22", "Windows 11 Enterprise", "HR", 2, "workstation", "corp"),
    SimHost(
        "WS-ENG-01", "10.10.10.31", "Windows 11 Enterprise", "Engineering", 2, "workstation", "corp"
    ),
    SimHost(
        "WS-ENG-02", "10.10.10.32", "Windows 11 Enterprise", "Engineering", 2, "workstation", "corp"
    ),
    SimHost(
        "WS-ENG-03", "10.10.10.33", "Windows 11 Enterprise", "Engineering", 2, "workstation", "corp"
    ),
    SimHost("WS-IT-01", "10.10.10.41", "Windows 11 Enterprise", "IT", 3, "workstation", "corp"),
)

USERS: tuple[SimUser, ...] = (
    SimUser("a.patel", "Anika Patel", "Finance", "standard", workstation="WS-FIN-01"),
    SimUser("m.chen", "Ming Chen", "Finance", "standard", workstation="WS-FIN-02"),
    SimUser("s.okafor", "Sade Okafor", "HR", "standard", workstation="WS-HR-01"),
    SimUser("l.garcia", "Luis Garcia", "HR", "standard", workstation="WS-HR-02"),
    SimUser("d.kim", "Dana Kim", "Engineering", "standard", workstation="WS-ENG-01"),
    SimUser("r.novak", "Rina Novak", "Engineering", "standard", workstation="WS-ENG-02"),
    SimUser("t.berg", "Tomas Berg", "Engineering", "standard", workstation="WS-ENG-03"),
    SimUser("k.ito", "Kenji Ito", "IT", "standard", workstation="WS-IT-01"),
    SimUser("it.admin", "IT Administration", "IT", "admin"),
    SimUser("da.kowalski", "Domain Admin (Kowalski)", "IT", "domain_admin"),
    SimUser("webadmin", "Web Administrator", "Digital", "elevated"),
    SimUser("svc_web", "IIS application pool", "Digital", "standard", is_service_account=True),
    SimUser("svc_app", "App tier service", "Engineering", "elevated", is_service_account=True),
    SimUser("svc_backup", "Backup job service", "IT", "elevated", is_service_account=True),
)

HOSTS_BY_NAME = {h.hostname: h for h in HOSTS}
USERS_BY_NAME = {u.username: u for u in USERS}

# Documentation-range addresses (RFC 5737).
ATTACKER_IP = "203.0.113.66"
C2_IP = "203.0.113.80"
C2_DOMAIN = "update.cdn-sync.example"
WEB_CLIENT_NET = "198.51.100."  # legitimate internet visitors of WEB-01
SCANNER_NET = "192.0.2."  # background internet scanning noise

WORKSTATIONS = tuple(h for h in HOSTS if h.role == "workstation")
STAFF = tuple(u for u in USERS if u.workstation)
