import pytest
from datetime import datetime, time, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.device import Device
from backend.app.models.access_schedule import AccessSchedule
from backend.app.models.patch_job import PatchJob
from backend.app.models.endpoint_update import EndpointUpdate
from backend.app.models.event import Event


TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_delete_device_permanently_cascades_and_removes_state():
    db = TestingSessionLocal()

    # Create a test device
    device = Device(
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.105",
        hostname="TEST-SIM-PC",
        device_type="computer",
        approval_status="approved",
        vlan_id=20,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    dev_id = device.id

    # Create associated schedule
    schedule = AccessSchedule(
        device_id=dev_id,
        start_time=time(8, 0, 0),
        end_time=time(17, 0, 0),
        days="daily",
        enabled=True,
    )
    db.add(schedule)

    # Create associated patch job
    job = PatchJob(
        device_id=dev_id,
        hostname="TEST-SIM-PC",
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.105",
        action="INSTALL_ALL_UPDATES",
        status="SCHEDULED",
    )
    db.add(job)

    # Create associated endpoint update telemetry
    update = EndpointUpdate(
        hostname="TEST-SIM-PC",
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.105",
        operating_system="Ubuntu",
        os_version="24.04",
        architecture="x86_64",
        update_status="up_to_date",
        last_checked=datetime.now(timezone.utc),
    )
    db.add(update)

    # Create associated event
    event = Event(
        event_type="device_test",
        message="Simulated event for device",
        device_id=dev_id,
    )
    db.add(event)
    db.commit()
    db.close()

    # Call DELETE /devices/{device_id}
    res = client.delete(f"/devices/{dev_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "deleted"
    assert data["device_id"] == dev_id

    # Verify device and all associated records are completely deleted
    db2 = TestingSessionLocal()
    assert db2.get(Device, dev_id) is None
    assert db2.scalars(select(AccessSchedule).where(AccessSchedule.device_id == dev_id)).first() is None
    assert db2.scalars(select(PatchJob).where(PatchJob.device_id == dev_id)).first() is None
    assert db2.scalars(select(EndpointUpdate).where(EndpointUpdate.mac_address == "00:11:22:33:44:55")).first() is None
    assert db2.scalars(select(Event).where(Event.device_id == dev_id)).first() is None

    # Verify a permanent deletion event was recorded
    del_event = db2.scalars(select(Event).where(Event.event_type == "device_permanently_deleted")).first()
    assert del_event is not None
    assert "00:11:22:33:44:55" in del_event.message

    # Reconnect test: If device connects again, it is created as a completely new machine
    new_res = client.post(
        "/devices/",
        json={
            "mac_address": "00:11:22:33:44:55",
            "ip_address": "192.168.1.105",
            "hostname": "TEST-SIM-PC",
        },
    )
    assert new_res.status_code == 201
    new_data = new_res.json()
    assert new_data["approval_status"] == "pending"  # Treated as brand new machine!
    db2.close()


def test_bulk_delete_devices_permanently():
    db = TestingSessionLocal()
    dev1 = Device(mac_address="00:AA:BB:CC:DD:01", hostname="SIM-MACHINE-01")
    dev2 = Device(mac_address="00:AA:BB:CC:DD:02", hostname="SIM-MACHINE-02")
    dev3 = Device(mac_address="00:AA:BB:CC:DD:03", hostname="KEEP-MACHINE-03")
    db.add_all([dev1, dev2, dev3])
    db.commit()
    id1, id2, id3 = dev1.id, dev2.id, dev3.id
    db.close()

    res = client.post("/devices/bulk-delete", json={"device_ids": [id1, id2]})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "bulk_deleted"
    assert data["deleted_count"] == 2

    db2 = TestingSessionLocal()
    assert db2.get(Device, id1) is None
    assert db2.get(Device, id2) is None
    assert db2.get(Device, id3) is not None  # Kept intact!
    db2.close()


def test_delete_nonexistent_device_returns_404():
    res = client.delete("/devices/999999")
    assert res.status_code == 404
