import asyncio

_subscribers: dict[str, list[asyncio.Queue]] = {
    "alerts":  [],
    "packets": [],
    "monitoring": []
}