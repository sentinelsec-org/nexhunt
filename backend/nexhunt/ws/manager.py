import json
import asyncio
import logging
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Broadcast hub for real-time events to connected frontend clients."""

    def __init__(self):
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)
        logger.info(f"WebSocket client connected. Total: {len(self._connections)}")

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self._connections:
                self._connections.remove(ws)
        logger.info(f"WebSocket client disconnected. Total: {len(self._connections)}")

    async def broadcast(self, channel: str, data: dict, event: str = "update"):
        """Send a message to all connected clients on a specific channel."""
        message = json.dumps({
            "channel": channel,
            "event": event,
            "data": data
        })

        disconnected = []
        async with self._lock:
            for ws in self._connections:
                try:
                    await ws.send_text(message)
                except Exception:
                    disconnected.append(ws)

        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    if ws in self._connections:
                        self._connections.remove(ws)

    @property
    def client_count(self) -> int:
        return len(self._connections)


# Global instance
ws_manager = WebSocketManager()
