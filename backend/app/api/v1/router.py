from fastapi import APIRouter

from app.api.v1.actions import router as actions_router
from app.api.v1.adversary import router as adversary_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.assets import router as assets_router
from app.api.v1.auth import router as auth_router
from app.api.v1.detections import router as detections_router
from app.api.v1.events import router as events_router
from app.api.v1.health import router as health_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.rules import router as rules_router
from app.api.v1.security_improvement import router as security_improvement_router
from app.api.v1.tenants import router as tenants_router

api_v1_router = APIRouter()

api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(tenants_router)
api_v1_router.include_router(assets_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(detections_router)
api_v1_router.include_router(rules_router)
api_v1_router.include_router(actions_router)
api_v1_router.include_router(adversary_router)
api_v1_router.include_router(security_improvement_router)
