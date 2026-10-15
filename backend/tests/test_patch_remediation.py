import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.device import Device
from backend.app.models.endpoint_update import EndpointUpdate
from backend.app.models.patch_job import PatchJob
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

    # Delete the job
    del_res = client.delete(f"/endpoint-updates/jobs/{job_id}")
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


