from fastapi import APIRouter

from app.api.v1.routes import demo, events, health, hosts, incidents, investigate

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(events.router)
api_router.include_router(hosts.router)
api_router.include_router(incidents.router)
api_router.include_router(incidents.analysis_router)
api_router.include_router(investigate.router)
api_router.include_router(demo.router)
