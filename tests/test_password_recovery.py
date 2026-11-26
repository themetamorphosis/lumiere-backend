from datetime import datetime, timedelta, timezone
from hashlib import sha256
from unittest.mock import Mock

import pytest

from app.api.endpoints import auth


@pytest.fixture
def sent_mail(monkeypatch):
    monkeypatch.setattr(auth.config.settings, "SMTP_HOST", "localhost")
    monkeypatch.setattr(auth.config.settings, "SMTP_FROM", "accounts@example.com")
    send = Mock()
    monkeypatch.setattr(auth, "send_reset_email", send)
    return send


@pytest.mark.asyncio
async def test_recovery_is_single_use_and_revokes_existing_credentials(client, db, test_user, sent_mail):
    tokens = (await client.post("/api/v1/auth/login", data={
        "username": test_user.email, "password": "TestPass123!",
    })).json()
    for email in (test_user.email.upper(), "unknown@example.com", test_user.email):
        response = await client.post("/api/v1/auth/password-reset/request", json={"email": email})
        assert (response.status_code, response.json()) == (202, {"ok": True})

    sent_mail.assert_called_once()
    recipient, token = sent_mail.call_args.args
    assert recipient == test_user.email
    await db.refresh(test_user)
    assert test_user.reset_token_digest == sha256(token.encode()).hexdigest()

    result = await client.post("/api/v1/auth/password-reset/confirm", json={"token": token, "password": "short"})
    assert result.status_code == 422
    data = {"token": token, "password": "ChangedPass123!"}
    result = await client.post("/api/v1/auth/password-reset/confirm", json=data)
    assert result.status_code == 200
    result = await client.post("/api/v1/auth/password-reset/confirm", json=data)
    assert result.status_code == 400

    me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 401
    refreshed = await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 401
    for password, status in (("TestPass123!", 400), ("ChangedPass123!", 200)):
        result = await client.post("/api/v1/auth/login", data={"username": test_user.email, "password": password})
        assert result.status_code == status


@pytest.mark.asyncio
async def test_recovery_rejects_expired_links(client, db, test_user, sent_mail):
    await client.post("/api/v1/auth/password-reset/request", json={"email": test_user.email})
    token = sent_mail.call_args.args[1]
    test_user.reset_token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db.commit()
    result = await client.post("/api/v1/auth/password-reset/confirm", json={
        "token": token, "password": "ChangedPass123!",
    })
    assert result.status_code == 400
