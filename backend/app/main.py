import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from .config import settings
from .database import Base, engine, SessionLocal
from .models.device import Device
from .models.event import Event

from .api.devices import router as devices_router
from .api.events import router as events_router
from .api.discovery import router as discovery_router

from .services.websocket_manager import manager


# ---------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------

Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------
# FASTAPI APPLICATION
# ---------------------------------------------------------

app = FastAPI(
    title=settings.app_name,
    description="Network & Endpoint Operations Platform",
    version="0.1.0",
)


# ---------------------------------------------------------
# CORS CONFIGURATION
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
],    
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# API ROUTERS
# ---------------------------------------------------------

app.include_router(devices_router)
app.include_router(events_router)
app.include_router(discovery_router)


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.get("/health")
def health_check():
    return {
        "status": "online",
        "application": settings.app_name,
        "environment": settings.app_env,
    }


# ---------------------------------------------------------
# ROOT ENDPOINT
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "message": "NETOPS Network & Endpoint Operations Platform",
        "version": "0.1.0",
    }


# ---------------------------------------------------------
# REAL-TIME EVENT BROADCASTER
# ---------------------------------------------------------

async def event_broadcaster():
    """
    Monitor the events table and broadcast new events
    to connected WebSocket clients.
    """

    last_event_id = 0

    while True:
        try:
            db = SessionLocal()

            try:
                events = db.scalars(
                    select(Event)
                    .where(Event.id > last_event_id)
                    .order_by(Event.id)
                ).all()

                for event in events:
                    await manager.broadcast(
                        {
                            "type": "event",
                            "event": {
                                "id": event.id,
                                "event_type": event.event_type,
                                "message": event.message,
                                "device_id": event.device_id,
                                "created_at": (
                                    event.created_at.isoformat()
                                ),
                            },
                        }
                    )

                    last_event_id = event.id

            finally:
                db.close()

        except Exception as error:
            print(
                f"[WEBSOCKET] Event broadcaster error: {error}"
            )

        await asyncio.sleep(1)


# ---------------------------------------------------------
# START EVENT BROADCASTER
# ---------------------------------------------------------

@app.on_event("startup")
async def startup_event_broadcaster():
    asyncio.create_task(
        event_broadcaster()
    )


# ---------------------------------------------------------
# WEBSOCKET EVENT CHANNEL
# ---------------------------------------------------------

@app.websocket("/ws/events")
async def websocket_events(
    websocket: WebSocket,
):
    await manager.connect(websocket)

    try:
        await websocket.send_json(
            {
                "type": "connection",
                "message": (
                    "NETOPS real-time event "
                    "channel connected"
                ),
            }
        )

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        manager.disconnect(websocket)

    except Exception:
        manager.disconnect(websocket)
