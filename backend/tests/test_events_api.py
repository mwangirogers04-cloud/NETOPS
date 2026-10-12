
from datetime import datetime
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from backend.app.api import events
from backend.app.main import app
from backend.app.models.event import Event


client = TestClient(app)


def test_get_events_returns_events_in_descending_id_order():
    first_event = Event(
        id=5,
        event_type="endpoint_recovered",
        message="TEST-PC is reporting again.",
        device_id=None,
        created_at=datetime(2026, 10, 11, 10, 0, 0),
    )

    second_event = Event(
        id=4,
        event_type="endpoint_stale",
        message="TEST-PC stopped reporting.",
        device_id=None,
        created_at=datetime(2026, 10, 11, 9, 0, 0),
    )

    db = MagicMock()
    db.scalars.return_value.all.return_value = [
        first_event,
        second_event,
    ]

    def override_get_db():
        yield db

    app.dependency_overrides[events.get_db] = override_get_db

    try:
        response = client.get("/events/")
    finally:
        app.dependency_overrides.pop(events.get_db, None)

    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["id"] == 5
    assert data[1]["id"] == 4
    assert data[0]["event_type"] == "endpoint_recovered"
    assert data[1]["event_type"] == "endpoint_stale"


def test_get_events_filters_by_event_type(monkeypatch):
    stale_event = Event(
        id=4,
        event_type="endpoint_stale",
        message="TEST-PC stopped reporting.",
        device_id=None,
        created_at=datetime(2026, 10, 11, 9, 0, 0),
    )

    db = MagicMock()
    db.scalars.return_value.all.return_value = [stale_event]

    def override_get_db():
        yield db

    app.dependency_overrides[events.get_db] = override_get_db

    try:
        response = client.get(
            "/events/?event_type=endpoint_stale"
        )
    finally:
        app.dependency_overrides.pop(events.get_db, None)

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["event_type"] == "endpoint_stale"
    query = db.scalars.call_args.args[0]
    sql = str(query)

    assert "events.event_type =" in sql

    compiled = query.compile()
    assert compiled.params["event_type_1"] == "endpoint_stale"



def test_get_events_accepts_pagination_parameters(monkeypatch):
    event = Event(
        id=4,
        event_type="endpoint_stale",
        message="TEST-PC stopped reporting.",
        device_id=None,
        created_at=datetime(2026, 10, 11, 9, 0, 0),
    )

    db = MagicMock()
    db.scalars.return_value.all.return_value = [event]

    def override_get_db():
        yield db

    app.dependency_overrides[events.get_db] = override_get_db

    try:
        response = client.get("/events/?limit=10&offset=0")
    finally:
        app.dependency_overrides.pop(events.get_db, None)

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert len(response.json()) == 1


def test_get_events_filters_by_event_type(monkeypatch):
    stale_event = Event(
        id=4,
        event_type="endpoint_stale",
        message="TEST-PC stopped reporting.",
        device_id=None,
        created_at=datetime(2026, 10, 11, 9, 0, 0),
    )

    db = MagicMock()
    db.scalars.return_value.all.return_value = [stale_event]

    def override_get_db():
        yield db

    app.dependency_overrides[events.get_db] = override_get_db

    try:
        response = client.get(
            "/events/?event_type=endpoint_stale"
        )
    finally:
        app.dependency_overrides.pop(events.get_db, None)

    assert response.status_code == 200
    assert response.json()[0]["event_type"] == "endpoint_stale"

    query = db.scalars.call_args.args[0]
    sql = str(query)

    assert "events.event_type =" in sql 
    compiled = query.compile()
    assert compiled.params["event_type_1"] == "endpoint_stale"


def test_get_events_applies_pagination(monkeypatch):
    event = Event(
        id=4,
        event_type="endpoint_stale",
        message="TEST-PC stopped reporting.",
        device_id=None,
        created_at=datetime(2026, 10, 11, 9, 0, 0),
    )

    db = MagicMock()
    db.scalars.return_value.all.return_value = [event]

    def override_get_db():
        yield db

    app.dependency_overrides[events.get_db] = override_get_db

    try:
        response = client.get("/events/?limit=10&offset=20")
    finally:
        app.dependency_overrides.pop(events.get_db, None)

    assert response.status_code == 200
    assert isinstance(response.json(), list)

    query = db.scalars.call_args.args[0]
    sql = str(query)

    assert "LIMIT" in sql
    assert "OFFSET" in sql
    assert query._limit_clause.value == 10
    assert query._offset_clause.value == 20
