from datetime import datetime, timedelta, timezone
from hashlib import sha256
import secrets
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from pydantic.networks import validate_email
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from app.api import dependencies
from app.core import security, config
from app.db import models
from app.middleware.rate_limit import limiter
from app.services.password_recovery import send_reset_email
from app.schemas import user as user_schema
import uuid

router = APIRouter()


async def find_email_accounts(db: AsyncSession, email: str) -> list[models.User]:
    """Find the exact identity first and detect ambiguous legacy case variants."""
    account = models.User
    rows = await db.scalars(
        select(account)
        .where(func.lower(account.email) == email.lower())
        .order_by((account.email == email).desc())
        .limit(2)
    )
    return list(rows)


@router.post("/register", response_model=user_schema.RegistrationSession | user_schema.User)
@limiter.limit("3/minute")
async def register_user(
    request: Request,
    response: Response,
    user_in: user_schema.UserCreate,
    create_session: bool = False,
    db: AsyncSession = Depends(dependencies.get_db),
):
    email = user_in.email.lower()
    duplicate_email = "An account with this email already exists."
    if await find_email_accounts(db, email):
        raise HTTPException(status_code=400, detail=duplicate_email)

    account = models.User(
        id=str(uuid.uuid4()),
        email=email,
        password=security.get_password_hash(user_in.password),
        name=user_in.name,
        image=user_in.image,
    )
    if create_session:
        account.token_family = str(uuid.uuid4())
        account.auth_version = str(uuid.uuid4())

    db.add(account)
    try:
        await db.commit()
    except IntegrityError:
        # New addresses are stored in a consistent case, so the unique email
        # constraint also covers simultaneous registrations.
        await db.rollback()
        raise HTTPException(status_code=400, detail=duplicate_email) from None
    await db.refresh(account)

    if not create_session:
        return account
    response.headers["Cache-Control"] = "no-store"
    return {
        "user": account,
        "session": issue_tokens(account.email, account.token_family, account.auth_version),
    }


# A real bcrypt hash to compare against when the account doesn't exist. Without
# it the miss path returns before hashing, and the response-time difference
# tells an attacker which emails are registered.
_DUMMY_PASSWORD_HASH = security.get_password_hash("not-a-real-password-placeholder")


@router.post("/login", response_model=user_schema.Token)
@limiter.limit("5/minute")
async def login_access_token(request: Request, db: AsyncSession = Depends(dependencies.get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        _, email = validate_email(form_data.username)
    except ValueError:
        accounts = []
    else:
        accounts = await find_email_accounts(db, email)
    user = accounts[0] if accounts and (len(accounts) == 1 or accounts[0].email == email) else None

    # Always run one comparison, whether or not the account exists, so both
    # paths cost the same.
    stored_hash = user.password if user and user.password else _DUMMY_PASSWORD_HASH
    password_ok = security.verify_password(form_data.password, stored_hash)

    if not user or not user.password or not password_ok:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    # If the password changed while we verified it, the old credential
    # cannot create a session after the password reset commits.
    auth_version = str(uuid.uuid4())
    family = str(uuid.uuid4())
    result = await db.execute(
        update(models.User)
        .where(models.User.id == user.id, models.User.password == stored_hash)
        .values(token_family=family, auth_version=auth_version)
    )
    await db.commit()
    if not result.rowcount:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    return issue_tokens(user.email, family, auth_version)


def issue_tokens(email: str, family: str, auth_version: str | None) -> dict:
    return {
        "access_token": security.create_access_token(email, auth_version=auth_version),
        "refresh_token": security.create_refresh_token(email, family, auth_version=auth_version),
        "token_type": "bearer",
    }


def refresh_claims(token: str) -> dict:
    try:
        payload = security.decode_token(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    if not security.verify_token_type(payload, "refresh") or not payload.get("sub") or not payload.get("family"):
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    return payload


@router.post("/refresh", response_model=user_schema.Token)
@limiter.limit("10/minute")
async def refresh_access_token(
    request: Request, db: AsyncSession = Depends(dependencies.get_db),
):
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    token = body.get("refresh_token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        raise HTTPException(status_code=400, detail="refresh_token is required")

    payload = refresh_claims(token)
    email = payload["sub"]
    auth_version = payload.get("auth_version")
    family = str(uuid.uuid4())
    # Compare and swap in PostgreSQL so a concurrent request cannot rotate
    # the same credential twice. A stale credential cannot revoke its successor.
    result = await db.execute(
        update(models.User)
        .where(
            models.User.email == email,
            models.User.token_family == payload["family"],
            models.User.auth_version == auth_version,
        )
        .values(token_family=family)
    )
    await db.commit()
    if not result.rowcount:
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")
    return issue_tokens(email, family, auth_version)


@router.post("/logout")
async def logout(
    request: Request,
    body: user_schema.TokenRefresh | None = None,
    db: AsyncSession = Depends(dependencies.get_db),
    token: str | None = Depends(dependencies.oauth2_scheme),
):
    # Revoke even when the access token has expired, without rotating a token
    # that the caller is about to discard.
    try:
        user = await dependencies.get_current_user(request, db, token)
    except HTTPException as exc:
        if exc.status_code != 401 or body is None:
            raise
        payload = refresh_claims(body.refresh_token)
        version = payload.get("auth_version")
        session_match = models.User.auth_version == version
        if version is None:
            session_match = session_match & (models.User.token_family == payload["family"])
        predicate = (models.User.email == payload["sub"]) & session_match
    else:
        predicate = (models.User.id == user.id) & (models.User.auth_version == user.auth_version)
    await db.execute(
        update(models.User).where(predicate).values(token_family=None, auth_version=str(uuid.uuid4()))
    )
    await db.commit()
    return {"ok": True}


RESET_LIFETIME = timedelta(minutes=30)
RESET_COOLDOWN = timedelta(minutes=1)


@router.post("/password-reset/request", status_code=202)
@limiter.limit("30/minute")
async def request_password_reset(
    request: Request,
    body: user_schema.PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(dependencies.get_db),
):
    settings = config.settings
    if not settings.SMTP_HOST or not settings.SMTP_FROM:
        raise HTTPException(status_code=503, detail="Password recovery is temporarily unavailable")

    accounts = await find_email_accounts(db, body.email)
    if len(accounts) != 1:
        return {"ok": True}

    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)
    result = await db.execute(
        update(models.User)
        .where(
            models.User.id == accounts[0].id,
            models.User.password.is_not(None),
            (models.User.reset_token_expires_at.is_(None))
            | (models.User.reset_token_expires_at <= now + RESET_LIFETIME - RESET_COOLDOWN),
        )
        .values(
            reset_token_digest=sha256(token.encode()).hexdigest(),
            reset_token_expires_at=now + RESET_LIFETIME,
        )
        .returning(models.User.email)
    )
    recipient = result.scalar_one_or_none()
    await db.commit()
    if recipient:
        background_tasks.add_task(send_reset_email, recipient, token)
    return {"ok": True}


@router.post("/password-reset/confirm")
@limiter.limit("10/minute")
async def confirm_password_reset(
    request: Request,
    body: user_schema.PasswordResetConfirmation,
    db: AsyncSession = Depends(dependencies.get_db),
):
    token = body.token.get_secret_value()
    invalid_link = "This reset link is invalid or expired. Request a new link."
    if len(token) != 43:
        raise HTTPException(status_code=400, detail=invalid_link)
    password = body.password.get_secret_value()
    if len(password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")
    try:
        user_schema.validate_password(password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    digest = sha256(token.encode()).hexdigest()
    result = await db.execute(
        select(models.User.id).where(
            models.User.reset_token_digest == digest,
            models.User.reset_token_expires_at > datetime.now(timezone.utc),
        )
    )
    user_id = result.scalar_one_or_none()
    if user_id is None:
        raise HTTPException(status_code=400, detail=invalid_link)

    hashed_password = security.get_password_hash(password)
    # Match the unexpired token again when updating. Only one consumer can
    # change the password, including when requests arrive on separate workers.
    result = await db.execute(
        update(models.User)
        .where(
            models.User.id == user_id,
            models.User.reset_token_digest == digest,
            models.User.reset_token_expires_at > datetime.now(timezone.utc),
        )
        .values(
            password=hashed_password,
            auth_version=str(uuid.uuid4()),
            token_family=None,
            reset_token_digest=None,
            reset_token_expires_at=None,
        )
    )
    await db.commit()
    if not result.rowcount:
        raise HTTPException(status_code=400, detail=invalid_link)
    return {"ok": True}


@router.get("/me", response_model=user_schema.User)
async def read_current_user(current_user: models.User = Depends(dependencies.get_current_user)):
    return current_user


@router.patch("/me", response_model=user_schema.User)
async def update_current_user(
    user_in: user_schema.UserUpdate,
    current_user: models.User = Depends(dependencies.get_current_user),
    db: AsyncSession = Depends(dependencies.get_db)
):
    update_data = user_in.model_dump(exclude_unset=True)

    # `current_password` is a credential, not a column — pull it out before the
    # setattr loop so it can never be written to the model.
    current_password = update_data.pop("current_password", None)

    if "password" in update_data:
        version = current_user.auth_version
        locked_user = await db.scalar(
            select(models.User)
            .where(models.User.id == current_user.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if locked_user is None or locked_user.auth_version != version:
            raise HTTPException(status_code=401, detail="Session expired")
        if not current_password:
            raise HTTPException(
                status_code=400,
                detail="current_password is required to change your password",
            )
        if not current_user.password or not security.verify_password(
            current_password, current_user.password
        ):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

    for field, value in update_data.items():
        if field == "password":
            setattr(current_user, field, security.get_password_hash(value))
        else:
            setattr(current_user, field, value)

    if "password" in update_data:
        # Every refresh token issued before the change must die with it —
        # otherwise changing a password after a compromise locks nobody out.
        current_user.token_family = None
        current_user.auth_version = str(uuid.uuid4())
        current_user.reset_token_digest = None
        current_user.reset_token_expires_at = None

    db.add(current_user)
    try:
        await db.commit()
    except IntegrityError:
        # `handle` is globally unique. Two people can claim the same one at the
        # same moment, so the index is the arbiter rather than a pre-check.
        await db.rollback()
        raise HTTPException(status_code=409, detail="That handle is already taken")
    await db.refresh(current_user)
    return current_user
