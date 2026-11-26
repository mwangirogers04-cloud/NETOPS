import asyncio
from contextlib import asynccontextmanager

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
from .services.l2_quarantine import sync_quarantined_targets_from_db, _is_cloud_host
from .services.passive_sniffer import start_passive_sniffer, stop_passive_sniffer
from .api.switches import router as switches_router
from .api.notifications import router as notifications_router
from .api.radius import router as radius_router
from .api.user_monitoring import router as user_monitoring_router
from .api.web_activity import router as web_activity_router

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
from .services.web_traffic_sniffer import (
    start_web_traffic_sniffer,
    stop_web_traffic_sniffer,
)
from .services.dns_server import (
    start_dns_server,
    stop_dns_server,
)


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

cors_origins_list = [
    origin.strip()
    for origin in settings.cors_origins.split(",")
    if origin.strip()
]
for explicit_origin in [
    "https://netops.co.ke",
    "https://www.netops.co.ke",
    "https://net-ops.ac.ke",
    "https://www.net-ops.ac.ke",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]:
    if explicit_origin not in cors_origins_list:
        cors_origins_list.append(explicit_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins_list,
    allow_origin_regex=r"https?://.*",
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
app.include_router(user_monitoring_router)
app.include_router(web_activity_router)


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

def _fetch_new_events_sync(last_event_id: int):
    db = SessionLocal()
    try:
        events = db.scalars(
            select(Event)
            .where(Event.id > last_event_id)
            .order_by(Event.id)
        ).all()
        return [
            {
                "id": ev.id,
                "event_type": ev.event_type,
                "message": ev.message,
                "device_id": ev.device_id,
                "actor": ev.actor,
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
            }
            for ev in events
        ]
    finally:
        try:
            if db.is_active:
                db.rollback()
        except Exception:
            pass
        db.close()


async def event_broadcaster():
    """
    Monitor the events table and broadcast new events
    to connected WebSocket clients without blocking the event loop.
    """
    last_event_id = 0
    def _get_latest_id():
        init_db = SessionLocal()
        try:
            latest_ev = init_db.scalars(
                select(Event).order_by(Event.id.desc()).limit(1)
            ).first()
            return latest_ev.id if latest_ev else 0
        finally:
            init_db.close()

    try:
        last_event_id = await asyncio.to_thread(_get_latest_id)
    except Exception:
        last_event_id = 0

    while True:
        try:
            # Only query DB if there are active WebSocket connections
            if getattr(manager, "active_connections", None):
                new_events = await asyncio.to_thread(_fetch_new_events_sync, last_event_id)
                for event in new_events:
                    event_payload = {
                        "id": event["id"],
                        "event_type": event["event_type"],
                        "message": event["message"],
                        "device_id": event["device_id"],
                        "created_at": event["created_at"],
                    }
                    await manager.broadcast(
                        {
                            "type": "event",
                            **event_payload,
                            "event": event_payload,
                        }
                    )

                    try:
                        if map_event_type_to_trigger(event["event_type"]):
                            dispatch_security_alert(
                                event_type=event["event_type"],
                                message=event["message"],
                                details={
                                    "device_id": event["device_id"],
                                    "actor": event["actor"],
                                    "event_id": event["id"],
                                },
                                sync=False,
                            )
                    except Exception as alert_err:
                        print(f"[ALERT] Error dispatching webhook alert: {alert_err}")

                    last_event_id = event["id"]

        except Exception as error:
            print(f"[WEBSOCKET] Event broadcaster note: {error}")

        await asyncio.sleep(2)


# ---------------------------------------------------------
# SCHEDULED PATCH & SWITCH TASKS
# ---------------------------------------------------------

def _run_patch_cycle_sync():
    db = SessionLocal()
    try:
        evaluate_auto_off_hours_policy(db)
        dispatch_due_scheduled_jobs(db)
        db.commit()
    except Exception as err:
        db.rollback()
        print(f"[PATCH-SCHEDULER] Error in patch scheduler loop: {err}")
    finally:
        try:
            if db.is_active:
                db.rollback()
        except Exception:
            pass
        db.close()


async def scheduled_patch_loop():
    """Evaluate scheduled patch remediation jobs and auto off-hours policy in a worker thread."""
    while True:
        try:
            await asyncio.to_thread(_run_patch_cycle_sync)
        except Exception:
            pass
        await asyncio.sleep(15)


def _run_switch_backup_sync(triggered_by: str = "auto_loop"):
    db = SessionLocal()
    try:
        execute_automated_backup_cycle(db, triggered_by=triggered_by)
        db.commit()
    except Exception as b_err:
        db.rollback()
        print(f"[SWITCH-BACKUP] Auto backup error: {b_err}")
    finally:
        try:
            if db.is_active:
                db.rollback()
        except Exception:
            pass
        db.close()


async def scheduled_switch_backup_loop():
    """Evaluate automated switch backup and CLI drift detection cycle."""
    if _is_cloud_host():
        return

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
                    await asyncio.to_thread(_run_switch_backup_sync, "auto_loop")
        except Exception as err:
            print(f"[SWITCH-BACKUP-SCHEDULER] Error in auto backup loop: {err}")

        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup tasks
    def _init_db():
        try:
            Base.metadata.create_all(bind=engine)
        except Exception as exc:
            print(f"[DB] Table verification note: {exc}")

        db = SessionLocal()
        try:
            seed_default_users(db)
            sync_quarantined_targets_from_db(db)
        except Exception as exc:
            print(f"[AUTH/L2] Error during startup sync: {exc}")
        finally:
            db.close()

    await asyncio.to_thread(_init_db)

    task_event_broadcaster = asyncio.create_task(event_broadcaster())
    task_schedule_loop = asyncio.create_task(schedule_enforcement_loop())
    task_health_monitor = asyncio.create_task(endpoint_health_monitor_loop())
    task_patch_loop = asyncio.create_task(scheduled_patch_loop())
    task_switch_backup = asyncio.create_task(scheduled_switch_backup_loop())

    try:
        start_passive_sniffer()
    except Exception as exc:
        print(f"[PASSIVE-SNIFFER] Startup note: {exc}")

    try:
        start_web_traffic_sniffer()
    except Exception as exc:
        print(f"[WEB-SNIFFER] Startup note: {exc}")

    try:
        start_dns_server()
    except Exception as exc:
        print(f"[DNS-SERVER] Startup note: {exc}")

    yield

    # Shutdown tasks
    try:
        stop_passive_sniffer()
    except Exception:
        pass
    try:
        stop_web_traffic_sniffer()
    except Exception:
        pass
    try:
        stop_dns_server()
    except Exception:
        pass

    for task in (task_event_broadcaster, task_schedule_loop, task_health_monitor, task_patch_loop, task_switch_backup):
        task.cancel()


app.router.lifespan_context = lifespan


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
