from fastapi import APIRouter
from api.services.packet import router as packet_router

router = APIRouter()

router.include_router(packet_router)