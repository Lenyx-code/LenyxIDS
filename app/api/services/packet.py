from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from api.utils.database import event_generator

router = APIRouter()

@router.get("/stream/packets", response_class=StreamingResponse,
    responses={
        200: {
            "description": "Flux SSE en temps réel des paquets générés",
            "content": {"text/event-stream": {}}
        }
    })
async def stream_packets(request: Request):
    return StreamingResponse(
        event_generator(request, "packets"),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )