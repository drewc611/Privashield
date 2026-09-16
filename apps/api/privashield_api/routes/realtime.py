from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["realtime"])


@router.websocket("/ws/events")
async def event_stream(websocket: WebSocket) -> None:
    requested = websocket.headers.get("sec-websocket-protocol", "")
    protocols = {item.strip() for item in requested.split(",") if item.strip()}
    selected_protocol = "privashield" if "privashield" in protocols else None
    await websocket.accept(subprotocol=selected_protocol)
    hub = websocket.app.state.event_hub
    try:
        async with hub.subscribe() as queue:
            while True:
                message = await queue.get()
                await websocket.send_json(message)
    except WebSocketDisconnect:
        return
