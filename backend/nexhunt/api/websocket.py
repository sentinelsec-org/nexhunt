from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from nexhunt.ws.manager import ws_manager

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """Main WebSocket endpoint for real-time updates."""
    await ws_manager.connect(ws)
    try:
        while True:
            # Keep connection alive, receive any client messages
            data = await ws.receive_text()
            # Client can send commands via WebSocket if needed
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws)
