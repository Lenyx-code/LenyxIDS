# api/utils/broadcast.py
import asyncio
import json
from api.utils.subscribers import _subscribers
from api.utils import loop_holder


def broadcast(channel: str, data: dict):
    if loop_holder.LOOP is None or loop_holder.LOOP.is_closed():
        print(f"[!] Broadcast ignoré : boucle asyncio non disponible ({channel})")
        return

    async def _push():
        for queue in list(_subscribers.get(channel, [])):  # copie pour éviter mutation
            try:
                queue.put_nowait(data)
            except asyncio.QueueFull:
                # Vider la queue si le client est trop lent
                try:
                    queue.get_nowait()
                    queue.put_nowait(data)
                except Exception:
                    pass

    future = asyncio.run_coroutine_threadsafe(_push(), loop_holder.LOOP)
    # Timeout court : si le push prend >1s, quelque chose cloche
    try:
        future.result(timeout=1.0)
    except Exception as e:
        print(f"[!] Broadcast timeout/error ({channel}): {e}")