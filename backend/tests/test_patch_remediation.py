import pytest
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

