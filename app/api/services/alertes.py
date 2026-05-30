from routes.stream import event_generator, router, StreamingResponse, Request

@router.get("/stream/alerts", response_class=StreamingResponse,
    responses={
        200: {
            "description": "Flux SSE en temps réel des alertes générées",
            "content": {"text/event-stream": {}}
        }
    })
async def stream_alerts(request: Request):
    return StreamingResponse(
        event_generator(request, "alerts"),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@router.get("/stream/count")
async def stream_count_alertes(request: Request):
    pass