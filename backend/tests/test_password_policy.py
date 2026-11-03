import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.auth_service import validate_password_complexity, create_access_token
from backend.app.database import SessionLocal
from backend.app.models.user import User

client = TestClient(app)


def test_validate_password_complexity_unit():
    # Valid password
    assert validate_password_complexity("StrongP@ss123", disallowed_terms=["john", "john@example.com"]) == "StrongP@ss123"

    # Contains username
    with pytest.raises(ValueError, match="Password cannot contain your name or email address"):
        validate_password_complexity("JohnDoeP@ss123", disallowed_terms=["johndoe", "john@example.com"])

    # Contains part of full name
    with pytest.raises(ValueError, match="Password cannot contain your name or email address"):
        validate_password_complexity("MwangiP@ss123", disallowed_terms=["Rogers Mwangi", "rogers@example.com"])

    # Contains email username part
    with pytest.raises(ValueError, match="Password cannot contain your name or email address"):
        validate_password_complexity("SuperAdmin_user123!", disallowed_terms=["some_user", "user123@example.com"])


def test_create_user_rejects_password_with_name_or_email():
    db = SessionLocal()
    try:
        db.query(User).filter(User.email == "alex.smith@example.com").delete()
        db.query(User).filter(User.username.in_(["AlexUser", "AlexSmith"])).delete()
        db.commit()

        admin = db.query(User).filter(User.username == "admin").first()
        token = create_access_token({"sub": admin.username, "role": admin.role, "id": admin.id})

        # Try to create user with password containing username
        res = client.post(
            "/users/",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "username": "AlexSmith",
                "email": "alex.smith@example.com",
                "phone_number": "0711223344",
                "role": "user",
                "password": "AlexSmith@2026!",
            },
        )
        assert res.status_code == 400
        assert "Password cannot contain your name or email address" in res.json().get("detail", "")

        # Try with password containing email prefix
        res2 = client.post(
            "/users/",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "username": "AlexUser",
                "email": "alex.smith@example.com",
                "phone_number": "0711223344",
                "role": "user",
                "password": "SmithSecure@2026!",
            },
        )
        assert res2.status_code == 400
        assert "Password cannot contain your name or email address" in res2.json().get("detail", "")

        # Valid password without personal info
        res3 = client.post(
            "/users/",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "username": "AlexUser",
                "email": "alex.smith@example.com",
                "phone_number": "0711223344",
                "role": "user",
                "password": "CompletelyUnrelated#2026!",
            },
        )
        assert res3.status_code == 201

        # Clean up created user
        db.query(User).filter(User.username == "AlexUser").delete()
        db.commit()
    finally:
        db.close()
