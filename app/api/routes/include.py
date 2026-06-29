from fastapi import APIRouter
from api.routes.alertes import router as alert_router
from api.routes.packet import router as packet_router
from api.routes.reports import router as reports_router
from api.routes.yara import router as yara_router
from api.routes.monitoring import router as monitoring_router

router = APIRouter()

for r in [packet_router, alert_router,
                  reports_router, yara_router, monitoring_router]:
           router.include_router(r)