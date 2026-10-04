from datetime import datetime

from pydantic import BaseModel, ConfigDict


class HostRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    ip_address: str
    operating_system: str
    department: str
    criticality: int
    role: str | None
    network_zone: str | None
    created_at: datetime
