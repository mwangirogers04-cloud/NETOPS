import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text

from .config import settings
from .database import Base, engine, SessionLocal
from .models.device import Device
from .models.event import Event
from .models.access_schedule import AccessSchedule
from .models.endpoint_update import EndpointUpdate
from .models.patch_job import PatchJob, UpdatePolicy
from .models.user import PasswordResetOTP, User, UserSession
from .models.firewall_config import FirewallConfig
from .models.switch_config import SwitchConfig
from .models.vlan_config import VlanConfig

from .api.devices import router as devices_router
from .api.events import router as events_router
from .api.discovery import router as discovery_router
from .api.reports import router as reports_router
from .api.access_schedules import router as access_schedules_router
from .api.endpoint_updates import router as endpoint_updates_router
from .api.cisco import router as cisco_router
from .api.sophos import router as sophos_router
from .api.firewall import router as firewall_router
from .api.simulation import router as simulation_router
from .api.auth import router as auth_router
from .api.users import router as users_router
from .api.switches import router as switches_router
from .api.notifications import router as notifications_router
from .api.radius import router as radius_router

from .services.auth_service import seed_default_users
from .services.webhook_service import dispatch_security_alert, map_event_type_to_trigger
from .services.switch_backup_service import execute_automated_backup_cycle, get_backup_schedule_settings

from .services.websocket_manager import manager
from .services.schedule_enforcement import schedule_enforcement_loop
from .services.endpoint_health_monitor import endpoint_health_monitor_loop
from .services.patch_remediation_service import (
    dispatch_due_scheduled_jobs,
    evaluate_auto_off_hours_policy,
)


# ---------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------

Base.metadata.create_all(bind=engine)

# Ensure newly introduced audit columns exist in database
try:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS actor VARCHAR(100);"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_by VARCHAR(100);"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;"))
except Exception:
    pass


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
        origin.strip()
        for origin in settings.cors_origins.split(",")
        if origin.strip()
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
app.include_router(reports_router)
app.include_router(access_schedules_router)
app.include_router(endpoint_updates_router)
app.include_router(cisco_router)
app.include_router(sophos_router)
app.include_router(firewall_router)
app.include_router(simulation_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(switches_router)
app.include_router(notifications_router)
app.include_router(radius_router)


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
    try:
        init_db = SessionLocal()
        try:
            latest_ev = init_db.scalars(
                select(Event).order_by(Event.id.desc()).limit(1)
            ).first()
            if latest_ev:
                last_event_id = latest_ev.id
        finally:
            init_db.close()
    except Exception:
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
                    event_payload = {
                        "id": event.id,
                        "event_type": event.event_type,
                        "message": event.message,
                        "device_id": event.device_id,
                        "created_at": (
                            event.created_at.isoformat()
                        ),
                    }
                    await manager.broadcast(
                        {
                            "type": "event",
                            **event_payload,
                            "event": event_payload,
                        }
                    )

                    # Trigger real-time webhook & security alert if event matches a trigger rule
                    try:
                        if map_event_type_to_trigger(event.event_type):
                            dispatch_security_alert(
                                event_type=event.event_type,
                                message=event.message,
                                details={
                                    "device_id": event.device_id,
                                    "actor": event.actor,
                                    "event_id": event.id,
                                },
                                sync=False,
                            )
                    except Exception as alert_err:
                        print(f"[ALERT] Error dispatching webhook alert: {alert_err}")

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


async def scheduled_patch_loop():
    """Evaluate scheduled patch remediation jobs and auto off-hours policy every 3 seconds."""
    while True:
        db = SessionLocal()
        try:
            evaluate_auto_off_hours_policy(db)
            dispatch_due_scheduled_jobs(db)
        except Exception as err:
            db.rollback()
            print(f"[PATCH-SCHEDULER] Error in patch scheduler loop: {err}")
        finally:
            db.close()
        await asyncio.sleep(3)


async def scheduled_switch_backup_loop():
    """Evaluate automated switch backup and CLI drift detection cycle."""
    while True:
        try:
            cfg = get_backup_schedule_settings()
            if cfg.get("enabled", True):
                interval_secs = max(60, int(cfg.get("interval_minutes", 60)) * 60)
                last_run_str = cfg.get("last_run_at")
                should_run = False
                if not last_run_str:
                    should_run = True
                else:
                    try:
                        last_run_dt = datetime.fromisoformat(last_run_str)
                        if last_run_dt.tzinfo is None:
                            last_run_dt = last_run_dt.replace(tzinfo=timezone.utc)
                        now_dt = datetime.now(timezone.utc)
                        if (now_dt - last_run_dt).total_seconds() >= interval_secs:
                            should_run = True
                    except Exception:
                        should_run = True

                if should_run:
                    db = SessionLocal()
                    try:
                        execute_automated_backup_cycle(db, triggered_by="auto_loop")
                    finally:
                        db.close()
        except Exception as err:
            print(f"[SWITCH-BACKUP-SCHEDULER] Error in auto backup loop: {err}")

        await asyncio.sleep(30)


@app.on_event("startup")
async def startup_event_broadcaster():
    # Seed default developer (super admin) and admin accounts
    db = SessionLocal()
    try:
        seed_default_users(db)
    except Exception as exc:
        print(f"[AUTH] Error seeding default users: {exc}")
    finally:
        db.close()

    asyncio.create_task(
        event_broadcaster()
    )

    asyncio.create_task(
        schedule_enforcement_loop()
    )

    asyncio.create_task(
        endpoint_health_monitor_loop()
    )

    asyncio.create_task(
        scheduled_patch_loop()
    )

    asyncio.create_task(
        scheduled_switch_backup_loop()
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
