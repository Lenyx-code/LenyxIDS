# api/utils/broadcast.py
import asyncio
from api.utils.subscribers import _subscribers
from api.utils import loop_holder


def _push_to_queues(channel: str, data: dict):
    """Pousse l'événement dans toutes les queues abonnées à ce canal (synchrone, non bloquant)."""
    for queue in list(_subscribers.get(channel, [])):  # copie pour éviter mutation pendant l'itération
        try:
            queue.put_nowait(data)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
                queue.put_nowait(data)
            except Exception:
                pass


async def _push_async(channel: str, data: dict):
    _push_to_queues(channel, data)


def broadcast(channel: str, data: dict):
    """
    Diffuse un événement à tous les abonnés SSE d'un canal.

    - Appelé depuis une route FastAPI async (thread de la boucle) → push direct.
    - Appelé depuis un thread externe à la boucle → planifié via
      run_coroutine_threadsafe.

    ⚠️ Ne JAMAIS faire un run_coroutine_threadsafe + future.result() bloquant
    depuis le thread qui exécute déjà cette boucle : ça deadlock (la boucle ne
    peut pas traiter la coroutine planifiée puisqu'elle est bloquée par
    l'attente synchrone de son propre résultat).
    """
    if loop_holder.LOOP is None or loop_holder.LOOP.is_closed():
        print(f"[!] Broadcast ignoré : boucle asyncio non disponible ({channel})")
        return

    try:
        running_loop = asyncio.get_running_loop()
    except RuntimeError:
        running_loop = None

    if running_loop is loop_holder.LOOP:
        _push_to_queues(channel, data)
        return

    future = asyncio.run_coroutine_threadsafe(_push_async(channel, data), loop_holder.LOOP)
    try:
        future.result(timeout=1.0)
    except Exception as e:
        print(f"[!] Broadcast timeout/error ({channel}): {e}")