import uuid
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_success(client: AsyncClient):
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    res = await client.post("/api/v1/auth/register", json={
        "email": email,
        "name": "New User",
        "password": "SecurePass123!",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == email
    assert data["name"] == "New User"
    assert "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient, test_user):
    res = await client.post("/api/v1/auth/register", json={
        "email": test_user.email,
        "name": "Dup User",
        "password": "SecurePass123!",
    })
    assert res.status_code == 400
    assert "already exists" in res.json()["detail"]


@pytest.mark.asyncio
async def test_register_weak_password(client: AsyncClient):
    res = await client.post("/api/v1/auth/register", json={
        "email": f"weak-{uuid.uuid4().hex[:8]}@example.com",
        "name": "Weak",
        "password": "short",
    })
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_email(client: AsyncClient):
    res = await client.post("/api/v1/auth/register", json={
        "email": "not-an-email",
        "name": "Bad Email",
        "password": "SecurePass123!",
    })
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, test_user):
    res = await client.post("/api/v1/auth/login", data={
        "username": test_user.email,
        "password": "TestPass123!",
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, test_user):
    res = await client.post("/api/v1/auth/login", data={
        "username": test_user.email,
        "password": "WrongPassword123!",
    })
    assert res.status_code == 400
    assert "Incorrect" in res.json()["detail"]


@pytest.mark.asyncio
async def test_login_nonexistent_user(client: AsyncClient):
    res = await client.post("/api/v1/auth/login", data={
        "username": "nobody@example.com",
        "password": "Whatever123!",
    })
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_read_me(client: AsyncClient, test_user, auth_headers):
    res = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == test_user.email
    assert data["name"] == test_user.name


@pytest.mark.asyncio
async def test_read_me_no_token(client: AsyncClient):
    res = await client.get("/api/v1/auth/me")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_read_me_invalid_token(client: AsyncClient):
    res = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_update_me_name(client: AsyncClient, test_user, auth_headers):
    res = await client.patch("/api/v1/auth/me", json={"name": "Updated Name"}, headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["name"] == "Updated Name"


@pytest.mark.asyncio
async def test_update_me_password(client: AsyncClient, test_user, auth_headers):
    # A password change now requires proof of the current one; see
    # test_security_hardening.py for the rejection cases.
    res = await client.patch(
        "/api/v1/auth/me",
        json={"password": "NewSecure123!", "current_password": "TestPass123!"},
        headers=auth_headers,
    )
    assert res.status_code == 200

    # Verify new password works
    login_res = await client.post("/api/v1/auth/login", data={
        "username": test_user.email,
        "password": "NewSecure123!",
    })
    assert login_res.status_code == 200


@pytest.mark.asyncio
async def test_register_and_sign_in_with_mixed_case_email(client: AsyncClient):
    email = f"Mixed-{uuid.uuid4().hex[:8]}@EXAMPLE.COM"
    password = "SecurePass123!"
    body = {"email": email, "name": "New User", "password": password}
    registered = await client.post("/api/v1/auth/register?create_session=true", json=body)
    assert registered.status_code == 200
    assert registered.headers["cache-control"] == "no-store"
    data = registered.json()
    assert data["user"]["email"] == email.lower()
    assert "refresh_token" in data["session"]

    me = await client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {data['session']['access_token']}",
    })
    assert me.status_code == 200
    assert me.json()["id"] == data["user"]["id"]

    signed_in = await client.post("/api/v1/auth/login", data={
        "username": f" {email.upper()} ", "password": password,
    })
    assert signed_in.status_code == 200
    duplicate = await client.post("/api/v1/auth/register", json={**body, "email": email.upper()})
    assert duplicate.status_code == 400


@pytest.mark.asyncio
async def test_case_insensitive_login_and_registration_check_existing_accounts(client, db, test_user):
    legacy_email = test_user.email.upper().replace("@EXAMPLE.COM", "@example.com")
    test_user.email = legacy_email
    await db.commit()

    signed_in = await client.post("/api/v1/auth/login", data={
        "username": legacy_email.lower(), "password": "TestPass123!",
    })
    assert signed_in.status_code == 200
    me = await client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {signed_in.json()['access_token']}",
    })
    assert me.json()["id"] == test_user.id
    duplicate = await client.post("/api/v1/auth/register", json={
        "email": legacy_email.lower(), "name": "Duplicate", "password": "SecurePass123!",
    })
    assert duplicate.status_code == 400
