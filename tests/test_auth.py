"""Tests for authentication service."""

import pytest
from fastapi.testclient import TestClient

from pyfarm.auth import create_app, UserCreate


@pytest.fixture
def client():
    """Create test client."""
    app = create_app()
    return TestClient(app)


def test_health(client):
    """Test health endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_register_user(client):
    """Test user registration."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "securepassword123",
            "full_name": "Test User",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "test@example.com"
    assert "observer" in data["roles"]


def test_register_duplicate_user(client):
    """Test registering duplicate user."""
    user_data = {
        "username": "testuser2",
        "email": "test2@example.com",
        "password": "securepassword123",
    }

    # First registration should succeed
    response1 = client.post("/api/v1/auth/register", json=user_data)
    assert response1.status_code == 200

    # Second registration should fail
    response2 = client.post("/api/v1/auth/register", json=user_data)
    assert response2.status_code == 400


def test_login(client):
    """Test user login."""
    # Register user first
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "logintest",
            "email": "login@example.com",
            "password": "securepassword123",
        },
    )

    # Login
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "logintest",
            "password": "securepassword123",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "logintest"


def test_login_invalid_password(client):
    """Test login with invalid password."""
    # Register user first
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "wrongpass",
            "email": "wrong@example.com",
            "password": "securepassword123",
        },
    )

    # Try login with wrong password
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "wrongpass",
            "password": "wrongpassword",
        },
    )

    assert response.status_code == 401


def test_get_current_user(client):
    """Test getting current user info."""
    # Register and login
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "metest",
            "email": "me@example.com",
            "password": "securepassword123",
        },
    )

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "metest",
            "password": "securepassword123",
        },
    )

    token = login_response.json()["access_token"]

    # Get current user
    response = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["username"] == "metest"


def test_verify_token(client):
    """Test token verification endpoint."""
    # Register and login
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "verifytest",
            "email": "verify@example.com",
            "password": "securepassword123",
        },
    )

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "verifytest",
            "password": "securepassword123",
        },
    )

    token = login_response.json()["access_token"]

    # Verify token
    response = client.post(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["username"] == "verifytest"
