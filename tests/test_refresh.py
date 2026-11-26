import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import models
from app.core import security


@pytest.mark.asyncio
async def test_refresh_issues_new_tokens(client: AsyncClient, test_user):
    # Login to get initial tokens
    login_res = await client.post("/api/v1/auth/login", data={
        "username": test_user.email,
        "password": "TestPass123!",
    })
    assert login_res.status_code == 200
    tokens = login_res.json()
    old_refresh = tokens["refresh_token"]

    # Refresh with the refresh token
    refresh_res = await client.post("/api/v1/auth/refresh", json={
        "refresh_token": old_refresh,
    })
    assert refresh_res.status_code == 200
    new_tokens = refresh_res.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    # Refresh token must change (new family claim); access may be same if generated same second
    assert new_tokens["refresh_token"] != old_refresh


@pytest.mark.asyncio
async def test_refresh_rejects_used_token(client: AsyncClient, test_user):
    # Login
    login_res = await client.post("/api/v1/auth/login", data={
        "username": test_user.email,
        "password": "TestPass123!",
    })
    refresh_token = login_res.json()["refresh_token"]

    # First refresh — should succeed
    res1 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert res1.status_code == 200

    # Replay the same refresh token — should fail (family rotated)
    res2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert res2.status_code == 401
    assert "revoked" in res2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_refresh_rejects_wrong_family(client: AsyncClient, test_user, db: AsyncSession):
    # Login
    login_res = await client.post("/api/v1/auth/login", data={
        "username": test_user.email,
        "password": "TestPass123!",
    })
    refresh_token = login_res.json()["refresh_token"]

    # Tamper: change the user's token_family in DB
    test_user.token_family = "tampered-family"
    await db.commit()

    res = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_family(client: AsyncClient, test_user):
    # Login to set token_family
    login_res = await client.post("/api/v1/auth/login", data={
        "username": test_user.email,
        "password": "TestPass123!",
    })
    refresh_token = login_res.json()["refresh_token"]

    # Logout
    logout_res = await client.post("/api/v1/auth/logout", headers={
        "Authorization": f"Bearer {login_res.json()['access_token']}",
    })
    assert logout_res.status_code == 200
    assert logout_res.json()["ok"] is True

    # Refresh after logout should fail
    refresh_res = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_res.status_code == 401


@pytest.mark.asyncio
async def test_refresh_missing_token(client: AsyncClient):
    res = await client.post("/api/v1/auth/refresh", json={})
    assert res.status_code == 400
    assert "required" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_refresh_invalid_token(client: AsyncClient):
    res = await client.post("/api/v1/auth/refresh", json={"refresh_token": "invalid.token.here"})
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_stale_refresh_leaves_rotated_session_intact(client, test_user):
    login = await client.post("/api/v1/auth/login", data={
        "username": test_user.email, "password": "TestPass123!",
    })
    initial = {"refresh_token": login.json()["refresh_token"]}
    rotated = await client.post("/api/v1/auth/refresh", json=initial)
    assert rotated.status_code == 200
    assert (await client.post("/api/v1/auth/refresh", json=initial)).status_code == 401
    next_refresh = await client.post("/api/v1/auth/refresh", json={
        "refresh_token": rotated.json()["refresh_token"],
    })
    assert next_refresh.status_code == 200


@pytest.mark.asyncio
async def test_logout_can_revoke_without_an_access_token(client, test_user):
    login = await client.post("/api/v1/auth/login", data={
        "username": test_user.email, "password": "TestPass123!",
    })
    tokens = login.json()
    body = {"refresh_token": tokens["refresh_token"]}
    assert (await client.post("/api/v1/auth/logout", json=body)).status_code == 200
    assert (await client.post("/api/v1/auth/refresh", json=body)).status_code == 401
    assert (await client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {tokens['access_token']}",
    })).status_code == 401
