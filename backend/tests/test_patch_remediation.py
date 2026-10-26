import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.access_schedule import AccessSchedule
from backend.app.models.device import Device
from backend.app.models.endpoint_update import EndpointUpdate
from backend.app.models.patch_job import PatchJob, UpdatePolicy
from backend.app.models.user import User
from backend.app.services.auth_service import create_access_token, hash_password
from backend.app.services.patch_remediation_service import (
    create_patch_job,
    dispatch_due_scheduled_jobs,
    get_pending_job_for_agent,
    is_local_machine,
    list_patch_jobs,
    update_patch_job_status,
)

TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_is_local_machine():
    assert is_local_machine(hostname="localhost") is True
    assert is_local_machine(ip_address="127.0.0.1") is True
    assert is_local_machine(hostname="remote-windows-pc", ip_address="192.168.100.222") is False


def test_create_patch_job_remote(db_session):
    job, is_local = create_patch_job(
        db=db_session,
        hostname="DESKTOP-TEST",
        ip_address="192.168.0.200",
        mac_address="AA:BB:CC:DD:EE:FF",
        action="INSTALL_ALL_UPDATES",
        auto_start_local=False,
    )

    assert job.id is not None
    assert job.hostname == "DESKTOP-TEST"
    assert job.status == "PENDING"
    assert job.progress_percent == 0
    assert is_local is False


def test_get_pending_job_for_agent(db_session):
    job, _ = create_patch_job(
        db=db_session,
        hostname="LAPTOP-CLIENT",
        ip_address="192.168.0.150",
        mac_address="00:11:22:33:44:55",
        auto_start_local=False,
    )

    # Search by hostname
    found = get_pending_job_for_agent(db_session, hostname="laptop-client")
    assert found is not None
    assert found.id == job.id

    # Search by MAC
    found_mac = get_pending_job_for_agent(db_session, mac_address="00:11:22:33:44:55")
    assert found_mac is not None
    assert found_mac.id == job.id

    # Non-existent
    assert get_pending_job_for_agent(db_session, hostname="unknown-device") is None


def test_update_patch_job_status(db_session):
    job, _ = create_patch_job(
        db=db_session,
        hostname="SERVER-01",
        ip_address="192.168.0.50",
        auto_start_local=False,
    )

    # In progress
    updated = update_patch_job_status(
        db=db_session,
        job_id=job.id,
        status="IN_PROGRESS",
        progress_percent=45,
        log_output="Downloading package updates...",
    )
    assert updated.status == "IN_PROGRESS"
    assert updated.progress_percent == 45
    assert updated.started_at is not None
    assert "Downloading package updates..." in updated.log_output

    # Completed
    completed = update_patch_job_status(
        db=db_session,
        job_id=job.id,
        status="COMPLETED",
        progress_percent=100,
        log_output="Updates installed successfully.",
    )
    assert completed.status == "COMPLETED"
    assert completed.progress_percent == 100
    assert completed.completed_at is not None


def test_api_trigger_and_list_patch_jobs(client, db_session):
    res = client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "REMOTE-DEV-1",
            "ip_address": "192.168.0.88",
            "mac_address": "11:22:33:44:55:66",
            "action": "INSTALL_ALL_UPDATES",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["hostname"] == "REMOTE-DEV-1"
    assert data["status"] == "PENDING"
    job_id = data["id"]

    # List jobs
    list_res = client.get("/endpoint-updates/jobs")
    assert list_res.status_code == 200
    jobs_data = list_res.json()
    assert len(jobs_data) >= 1
    assert jobs_data[0]["id"] == job_id

    # Get single job
    get_res = client.get(f"/endpoint-updates/jobs/{job_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == job_id


def test_api_agent_status_and_poll(client, db_session):
    # Queue a job
    trigger_res = client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "WIN-WORKSTATION",
            "ip_address": "192.168.0.77",
            "action": "INSTALL_ALL_UPDATES",
        },
    )
    job_id = trigger_res.json()["id"]

    # Poll command
    poll_res = client.get("/endpoint-updates/commands/WIN-WORKSTATION")
    assert poll_res.status_code == 200
    assert poll_res.json()["command"] == "INSTALL_ALL_UPDATES"
    assert poll_res.json()["job_id"] == job_id

    # Agent reports in-progress
    status_res = client.post(
        f"/endpoint-updates/jobs/{job_id}/status",
        json={
            "status": "IN_PROGRESS",
            "progress_percent": 50,
            "log_output": "Installing KB5034441...",
        },
    )
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "IN_PROGRESS"
    assert status_res.json()["progress_percent"] == 50

    # Agent reports completed
    complete_res = client.post(
        f"/endpoint-updates/jobs/{job_id}/status",
        json={
            "status": "COMPLETED",
            "progress_percent": 100,
            "log_output": "All updates installed.",
        },
    )
    assert complete_res.status_code == 200
    assert complete_res.json()["status"] == "COMPLETED"


def test_api_heartbeat_includes_pending_command(client, db_session):
    # Queue job
    client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "HEARTBEAT-HOST",
            "ip_address": "192.168.0.99",
            "mac_address": "AA:11:22:33:44:99",
        },
    )

    # Heartbeat report
    report_res = client.post(
        "/endpoint-updates/",
        json={
            "hostname": "HEARTBEAT-HOST",
            "mac_address": "AA:11:22:33:44:99",
            "ip_address": "192.168.0.99",
            "operating_system": "Windows",
            "os_version": "11 Pro",
            "architecture": "x86_64",
            "update_status": "updates_available",
            "pending_updates": 3,
        },
    )
    assert report_res.status_code == 200
    report_data = report_res.json()
    assert report_data["pending_command"] is not None
    assert report_data["pending_command"]["action"] == "INSTALL_ALL_UPDATES"


def test_api_trigger_with_invalid_device_id_succeeds(client, db_session):
    res = client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "FOREIGN-KEY-TEST",
            "ip_address": "192.168.0.210",
            "device_id": 999999,
            "action": "INSTALL_ALL_UPDATES",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["hostname"] == "FOREIGN-KEY-TEST"
    assert data["status"] == "PENDING"


def test_endpoint_updates_deduplication_and_patch_completion(client, db_session):
    # Step 1: Endpoint reports with machine_id and pending updates
    report_res = client.post(
        "/endpoint-updates/",
        json={
            "hostname": "SYNC-TEST-PC",
            "mac_address": "EE:22:33:44:55:66",
            "ip_address": "192.168.0.188",
            "machine_id": "machine-uuid-12345",
            "operating_system": "Linux",
            "os_version": "Debian",
            "architecture": "x86_64",
            "update_status": "updates_available",
            "pending_updates": 1901,
        },
    )
    assert report_res.status_code == 200

    # Verify initial list shows 1901 updates
    get_res = client.get("/endpoint-updates/")
    assert get_res.status_code == 200
    endpoints = [e for e in get_res.json() if e["hostname"] == "SYNC-TEST-PC"]
    assert len(endpoints) == 1
    assert endpoints[0]["pending_updates"] == 1901

    # Step 2: Trigger update job
    job_res = client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "SYNC-TEST-PC",
            "mac_address": "EE:22:33:44:55:66",
            "ip_address": "192.168.0.188",
            "machine_id": "machine-uuid-12345",
            "action": "INSTALL_ALL_UPDATES",
        },
    )
    assert job_res.status_code == 200
    job_id = job_res.json()["id"]

    # Step 3: Complete job
    status_res = client.post(
        f"/endpoint-updates/jobs/{job_id}/status",
        json={
            "status": "COMPLETED",
            "progress_percent": 100,
            "log_output": "All updates installed successfully.",
        },
    )
    assert status_res.status_code == 200

    # Step 4: Verify list endpoint now shows 0 pending updates and up_to_date
    get_res2 = client.get("/endpoint-updates/")
    assert get_res2.status_code == 200
    endpoints2 = [e for e in get_res2.json() if e["hostname"] == "SYNC-TEST-PC"]
    assert len(endpoints2) == 1
    assert endpoints2[0]["pending_updates"] == 0
    assert endpoints2[0]["update_status"] == "up_to_date"


def test_cancel_and_delete_patch_job(client, db_session):
    # Queue a job
    create_res = client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "CANCEL-TEST-HOST",
            "ip_address": "192.168.0.77",
            "action": "INSTALL_ALL_UPDATES",
        },
    )
    assert create_res.status_code == 200
    job_id = create_res.json()["id"]

    # Cancel the job
    cancel_res = client.post(f"/endpoint-updates/jobs/{job_id}/cancel")
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

    # 1. Unauthenticated delete is rejected (401)
    del_unauth = client.delete(f"/endpoint-updates/jobs/{job_id}")
    assert del_unauth.status_code == 401

    # 2. Administrator cannot delete patch job (403)
    admin = User(
        username="patch_admin",
        email="patch_admin@example.com",
        hashed_password=hash_password("Admin@1234"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    dev = User(
        username="patch_dev",
        email="patch_dev@example.com",
        hashed_password=hash_password("Dev@1234"),
        role="super_admin",
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([admin, dev])
    db_session.commit()

    admin_token = create_access_token({"sub": admin.username, "role": admin.role, "user_id": admin.id})
    dev_token = create_access_token({"sub": dev.username, "role": dev.role, "user_id": dev.id})

    del_admin = client.delete(f"/endpoint-updates/jobs/{job_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert del_admin.status_code == 403
    assert "super administrator" in del_admin.json()["detail"].lower()

    # 3. Super Admin can delete the job
    del_res = client.delete(f"/endpoint-updates/jobs/{job_id}", headers={"Authorization": f"Bearer {dev_token}"})
    assert del_res.status_code == 200

    # Verify not found
    get_res = client.get(f"/endpoint-updates/jobs/{job_id}")
    assert get_res.status_code == 404


def test_schedule_patch_job_future_and_dispatch_due(client, db_session):
    now_utc = datetime.now(timezone.utc)
    future_time = now_utc + timedelta(hours=2)

    # 1. Create a job scheduled in the future
    create_res = client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "SCHEDULED-AGENT-1",
            "ip_address": "192.168.1.188",
            "action": "INSTALL_ALL_UPDATES",
            "scheduled_at": future_time.isoformat(),
        },
    )
    assert create_res.status_code == 200
    job_data = create_res.json()
    job_id = job_data["id"]
    assert job_data["status"] == "SCHEDULED"
    assert job_data["scheduled_at"] is not None

    # 2. Verify agent check-in polling ignores this job because it's not due yet
    pending = get_pending_job_for_agent(db_session, hostname="SCHEDULED-AGENT-1")
    assert pending is None

    # 3. Running dispatch when not due should return 0 jobs
    dispatched = dispatch_due_scheduled_jobs(db_session)
    assert len(dispatched) == 0

    # 4. Fast-forward scheduled time to the past
    job_db = db_session.query(PatchJob).filter(PatchJob.id == job_id).first()
    assert job_db is not None
    job_db.scheduled_at = now_utc - timedelta(minutes=5)
    db_session.commit()

    # 5. Dispatch due jobs
    dispatched_due = dispatch_due_scheduled_jobs(db_session)
    assert len(dispatched_due) == 1
    assert dispatched_due[0].id == job_id
    assert dispatched_due[0].status == "PENDING"

    # 6. Now the agent polling should find this job ready to execute
    pending_now = get_pending_job_for_agent(db_session, hostname="SCHEDULED-AGENT-1")
    assert pending_now is not None
    assert pending_now.id == job_id


def test_cancel_scheduled_patch_job(client, db_session):
    now_utc = datetime.now(timezone.utc)
    future_time = now_utc + timedelta(hours=4)

    create_res = client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "CANCEL-SCHEDULED-HOST",
            "ip_address": "192.168.1.199",
            "action": "INSTALL_ALL_UPDATES",
            "scheduled_at": future_time.isoformat(),
        },
    )
    assert create_res.status_code == 200
    job_id = create_res.json()["id"]
    assert create_res.json()["status"] == "SCHEDULED"

    # Cancel the scheduled job
    cancel_res = client.post(f"/endpoint-updates/jobs/{job_id}/cancel")
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

    # Make the time past and verify dispatch does not pick up cancelled job
    job_db = db_session.query(PatchJob).filter(PatchJob.id == job_id).first()
    job_db.scheduled_at = now_utc - timedelta(minutes=10)
    db_session.commit()

    dispatched = dispatch_due_scheduled_jobs(db_session)
    assert not any(j.id == job_id for j in dispatched)


def test_run_patch_job_now_pending_and_scheduled(client, db_session):
    # 1. Create a pending job
    create_res = client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "REMOTE-QUEUE-TEST",
            "ip_address": "192.168.1.77",
            "action": "INSTALL_ALL_UPDATES",
        },
    )
    assert create_res.status_code == 200
    job_id = create_res.json()["id"]
    assert create_res.json()["status"] == "PENDING"

    # 2. Trigger run-now / continue update
    run_res = client.post(f"/endpoint-updates/jobs/{job_id}/run-now")
    assert run_res.status_code == 200
    data = run_res.json()
    assert data["status"] in ("IN_PROGRESS", "COMPLETED")
    assert "Manual execution triggered" in data["log_output"]


def test_get_endpoint_updates_includes_all_online_devices(client, db_session):
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(hours=2)

    # 1. Device that is online with an old EndpointUpdate
    dev1 = Device(
        mac_address="F0:1F:AF:4C:6A:E9",
        ip_address="192.168.0.12",
        hostname="DELL-PC",
        device_type="computer",
        status="online",
        approval_status="approved",
    )
    db_session.add(dev1)

    old_update = EndpointUpdate(
        hostname="DELL-PC",
        mac_address="F0:1F:AF:4C:6A:E9",
        ip_address="192.168.0.12",
        machine_id="F01FAF4C6AE9",
        operating_system="Windows",
        os_version="11/10",
        architecture="AMD64",
        update_status="stale",  # previously stale
        pending_updates=2,
        last_checked=old_time,
    )
    db_session.add(old_update)

    # 2. Device that is online but has no EndpointUpdate record at all
    dev2 = Device(
        mac_address="7C:5A:1C:A4:0B:10",
        ip_address="192.168.0.10",
        hostname="SOPHOS-GATEWAY",
        device_type="router",
        status="online",
        approval_status="approved",
    )
    db_session.add(dev2)
    db_session.commit()

    # Query GET /endpoint-updates/
    res = client.get("/endpoint-updates/")
    assert res.status_code == 200
    data = res.json()

    # Both online devices should be represented
    dell_entry = next((e for e in data if e["mac_address"] == "F0:1F:AF:4C:6A:E9"), None)
    assert dell_entry is not None
    assert dell_entry["is_online"] is True
    assert dell_entry["device_status"] == "online"
    # An online machine should never report status "stale"
    assert dell_entry["update_status"] != "stale"
    assert dell_entry["update_status"] == "updates_available"

    sophos_entry = next((e for e in data if e["mac_address"] == "7C:5A:1C:A4:0B:10"), None)
    assert sophos_entry is not None
    assert sophos_entry["is_online"] is True
    assert sophos_entry["device_status"] == "online"
    assert "working_hours" in sophos_entry


def test_off_hours_scheduling_and_working_hours_conflict_guard(client, db_session):
    from datetime import time as dt_time

    # 1. Create a device with custom working hours 00:00 - 23:00 daily so current time (if before 23:00) or a midday time is inside working hours
    dev = Device(
        mac_address="AA:BB:CC:11:22:33",
        ip_address="192.168.0.155",
        hostname="WORK-HOURS-PC",
        device_type="computer",
        status="online",
        approval_status="approved",
    )
    db_session.add(dev)
    db_session.flush()

    sched = AccessSchedule(
        device_id=dev.id,
        enabled=True,
        start_time=dt_time(8, 0, 0),
        end_time=dt_time(17, 0, 0),
        days="daily",
    )
    db_session.add(sched)
    db_session.commit()

    # 2. Check working hours via API for 11:00 AM tomorrow (inside working hours)
    tomorrow_11am = (datetime.now() + timedelta(days=1)).replace(hour=11, minute=0, second=0, microsecond=0)
    check_res = client.post(
        "/endpoint-updates/working-hours-check",
        json={
            "hostname": "WORK-HOURS-PC",
            "device_id": dev.id,
            "scheduled_at": tomorrow_11am.isoformat(),
        },
    )
    assert check_res.status_code == 200
    check_data = check_res.json()
    assert check_data["working_hours"]["source"] == "device_access_schedule"
    assert check_data["schedule_check"]["is_in_working_hours"] is True
    assert "17:05" in check_data["schedule_check"]["suggested_off_hours_display"]

    # 3. Attempting to schedule at 11:00 AM with respect_working_hours=True should be rejected (400)
    reject_res = client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "WORK-HOURS-PC",
            "device_id": dev.id,
            "ip_address": "192.168.0.155",
            "scheduled_at": tomorrow_11am.isoformat(),
            "respect_working_hours": True,
            "force_working_hours": False,
        },
    )
    assert reject_res.status_code == 400
    assert "working hours" in reject_res.json()["detail"].lower()

    # 4. Scheduling with schedule_mode="off_hours" automatically schedules outside working hours (after 17:00)
    off_res = client.post(
        "/endpoint-updates/jobs",
        json={
            "hostname": "WORK-HOURS-PC",
            "device_id": dev.id,
            "ip_address": "192.168.0.155",
            "schedule_mode": "off_hours",
        },
    )
    assert off_res.status_code == 200
    off_job = off_res.json()
    assert off_job["status"] == "SCHEDULED"
    assert off_job["scheduled_at"] is not None
    assert "[OFF-WORKING HOURS WINDOW]" in off_job["log_output"]


def test_update_policy_and_bulk_schedule_off_hours(client, db_session):
    # 1. Get default policy
    pol_res = client.get("/endpoint-updates/policy")
    assert pol_res.status_code == 200
    pol = pol_res.json()
    assert pol["default_working_start"] == "08:00"
    assert pol["default_working_end"] == "17:00"

    # 2. Update policy
    put_res = client.put(
        "/endpoint-updates/policy",
        json={
            "default_working_start": "09:00",
            "default_working_end": "18:00",
            "default_working_days": "weekdays",
            "auto_off_hours_enabled": False,
            "block_working_hours_schedule": True,
            "post_work_delay_minutes": 10,
        },
    )
    assert put_res.status_code == 200
    assert put_res.json()["default_working_start"] == "09:00"
    assert put_res.json()["post_work_delay_minutes"] == 10

    # 3. Report an endpoint needing updates
    client.post(
        "/endpoint-updates/",
        json={
            "hostname": "BULK-OFF-HOURS-PC",
            "mac_address": "CC:DD:EE:FF:00:11",
            "ip_address": "192.168.0.190",
            "operating_system": "Linux",
            "os_version": "Ubuntu 24.04",
            "architecture": "x86_64",
            "update_status": "updates_available",
            "pending_updates": 12,
        },
    )

    # 4. Bulk schedule all pending updates for off-hours
    bulk_res = client.post("/endpoint-updates/schedule-off-hours-all")
    assert bulk_res.status_code == 200
    jobs = bulk_res.json()
    assert any(j["hostname"] == "BULK-OFF-HOURS-PC" and j["status"] == "SCHEDULED" for j in jobs)


def test_orphaned_remote_job_at_70_percent_reconciles_to_completed(client, db_session):
    """
    If a remote machine update job is orphaned at 70% in-progress due to service restart,
    reconciliation must complete it and synchronize the endpoint baseline to up_to_date.
    """
    dev = Device(
        hostname="REMOTE-70PCT-PC",
        mac_address="70:70:70:70:70:70",
        ip_address="192.168.0.70",
        device_type="computer",
        approval_status="approved",
        enforcement_status="allowed",
        internet_access_authorized=True,
        status="online",
    )
    db_session.add(dev)
    db_session.commit()

    past_time = datetime.now(timezone.utc) - timedelta(seconds=30)
    job = PatchJob(
        device_id=dev.id,
        hostname=dev.hostname,
        mac_address=dev.mac_address,
        ip_address=dev.ip_address,
        status="IN_PROGRESS",
        progress_percent=70,
        started_at=past_time,
        log_output="[Log] Applying system patches and verifying integrity...",
    )
    db_session.add(job)

    ep = EndpointUpdate(
        hostname=dev.hostname,
        mac_address=dev.mac_address,
        ip_address=dev.ip_address,
        operating_system="Linux",
        os_version="Ubuntu 24.04",
        architecture="x86_64",
        update_status="updates_available",
        pending_updates=3,
        last_checked=datetime.now(timezone.utc),
    )
    db_session.add(ep)
    db_session.commit()

    # Run scheduled jobs reconciliation
    dispatch_due_scheduled_jobs(db_session)
    db_session.refresh(job)

    assert job.status == "COMPLETED"
    assert job.progress_percent == 100

    # Query GET /endpoint-updates/
    res = client.get("/endpoint-updates/")
    assert res.status_code == 200
    records = res.json()
    matched = [r for r in records if r["mac_address"] == "70:70:70:70:70:70"]
    assert len(matched) == 1
    assert matched[0]["update_status"] == "up_to_date"
    assert matched[0]["pending_updates"] == 0


def test_endpoint_updates_zero_pending_is_not_updates_available(client, db_session):
    """
    An endpoint with 0 pending updates must report update_status='up_to_date',
    never 'updates_available' (avoiding 'Needs Updates' with 0 pending).
    """
    dev = Device(
        hostname="CLEAN-WORKSTATION",
        mac_address="88:88:88:88:88:88",
        ip_address="192.168.0.88",
        device_type="computer",
        approval_status="approved",
        enforcement_status="allowed",
        internet_access_authorized=True,
        status="online",
    )
    db_session.add(dev)
    db_session.commit()

    res = client.get("/endpoint-updates/")
    assert res.status_code == 200
    records = res.json()
    clean_rec = [r for r in records if r["mac_address"] == "88:88:88:88:88:88"][0]
    assert clean_rec["pending_updates"] == 0
    assert clean_rec["update_status"] == "up_to_date"





