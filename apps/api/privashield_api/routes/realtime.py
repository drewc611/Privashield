from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["realtime"])


@router.websocket("/ws/events")
async def event_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    hub = websocket.app.state.event_hub
    try:
        async with hub.subscribe() as queue:
            while True:
                message = await queue.get()
                await websocket.send_json(message)
    except WebSocketDisconnect:
        return
