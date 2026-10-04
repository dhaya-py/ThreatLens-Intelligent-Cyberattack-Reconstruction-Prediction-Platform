from fastapi import APIRouter, HTTPException

from app.core.database import DbSession
from app.repositories.inventory import HostRepository
from app.schemas.hosts import HostRead

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=list[HostRead], summary="List hosts")
def list_hosts(db: DbSession) -> list[HostRead]:
    return [HostRead.model_validate(h) for h in HostRepository(db).all()]


@router.get("/{host_id}", response_model=HostRead, summary="Get one host")
def get_host(db: DbSession, host_id: int) -> HostRead:
    host = HostRepository(db).get(host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    return HostRead.model_validate(host)
