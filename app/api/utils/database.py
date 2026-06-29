# api/utils/database.py
from fastapi import Request
from api.utils.subscribers import _subscribers 
import asyncio
import json

async def event_generator(request: Request, channel: str):
    """Générateur SSE — écoute uniquement les NOUVEAUX événements"""
    queue = asyncio.Queue(maxsize=50)

    if channel not in _subscribers:
        _subscribers[channel] = []
    _subscribers[channel].append(queue)

    try:
        yield "data: {\"connected\": true}\n\n"

        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                yield f"data: {json.dumps(event, default=str)}\n\n"
            except asyncio.TimeoutError:
                yield ": ping\n\n"

    finally:
        if queue in _subscribers.get(channel, []):
            _subscribers[channel].remove(queue)