from typing import List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.api import dependencies
from app.db import models
from app.schemas import watchlist as watchlist_schema
from app.api.endpoints.media import get_cached, enrich_media_cache
from app.services.media_service import fetch_catalogue_metadata, get_cached_bulk
from app.db.database import AsyncSessionLocal
import uuid
import logging

router = APIRouter()
logger = logging.getLogger(__name__)


METADATA_FIELDS = ("coverUrl", "genres", "runtime", "description")


async def _background_enrich(
    title: str, media_type: str, year: int | None, item_id: str, tmdb_id: int | None = None,
):
    """Fill missing metadata and keep it tied to the saved edition."""
    async with AsyncSessionLocal() as db:
        try:
            if tmdb_id is not None:
                metadata = await fetch_catalogue_metadata(tmdb_id, media_type)
            else:
                await enrich_media_cache(db, title, media_type, year)
                cached = await get_cached(db, title, media_type, year)
                metadata = {field: getattr(cached, field) for field in METADATA_FIELDS} if cached else {}

            if not metadata:
                return
            item = await db.get(models.WatchlistItem, item_id)
            if not item or (tmdb_id is None and (item.title != title or item.year != year)):
                return

            changes = {
                field: value for field, value in metadata.items()
                if value is not None and metadata_missing(field, getattr(item, field))
            }
            for field, value in changes.items():
                setattr(item, field, value)
            if changes:
                await db.commit()
                logger.info("Enriched watchlist item %s", item_id)
        except Exception as exc:
            await db.rollback()
            logger.warning("Metadata enrichment failed for %s: %s", item_id, exc.__class__.__name__)


def metadata_missing(field: str, value: object) -> bool:
    return value is None if field == "runtime" else not value


@router.get("", response_model=watchlist_schema.WatchlistPage)
async def get_watchlist(
    current_user: models.User = Depends(dependencies.get_current_user),
    db: AsyncSession = Depends(dependencies.get_db),
    # Defaults to a page rather than the whole library. `0` still means "all"
    # for callers that ask for it explicitly. Flipping this default is safe
    # only because the frontend now always sends an explicit limit and follows
    # `has_more` — see REMEDIATION_PLAN.md 2.6/2.10 for the deploy ordering.
    limit: int = Query(default=100, ge=0, le=500, description="Max items to return. 0 = all"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    # Get total count
    count_stmt = select(func.count()).select_from(models.WatchlistItem).where(
        models.WatchlistItem.userId == current_user.id
    )
    total = (await db.execute(count_stmt)).scalar()

    # Get page
    q = (
        select(models.WatchlistItem)
        .filter(models.WatchlistItem.userId == current_user.id)
        .order_by(models.WatchlistItem.updatedAt.desc(), models.WatchlistItem.id)
    )
    if offset > 0:
        q = q.offset(offset)
    if limit > 0:
        q = q.limit(limit)
    result = await db.execute(q)
    items = result.scalars().all()

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        # limit=0 means "return everything", so nothing can remain after it.
        "has_more": (offset + limit) < total if limit > 0 else False,
    }

@router.post("", response_model=watchlist_schema.WatchlistItem)
async def create_watchlist_item(
    item_in: watchlist_schema.WatchlistItemCreate,
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(dependencies.get_current_user),
    db: AsyncSession = Depends(dependencies.get_db)
):
    cached = None
    if item_in.tmdbId is None:
        cached = await get_cached(db, item_in.title, item_in.mediaType, item_in.year)
    item_data = with_cached_metadata(item_in, cached)

    db_item = models.WatchlistItem(
        id=str(uuid.uuid4()),
        userId=current_user.id,
        **item_data
    )
    db.add(db_item)
    try:
        await db.commit()
    except IntegrityError:
        # The identity index also handles simultaneous additions.
        await db.rollback()
        raise HTTPException(status_code=400, detail="Item already exists in your watchlist")
    await db.refresh(db_item)

    if any(metadata_missing(field, item_data[field]) for field in METADATA_FIELDS):
        background_tasks.add_task(
            _background_enrich, item_in.title, item_in.mediaType, item_in.year, db_item.id, item_in.tmdbId
        )
    return db_item


def with_cached_metadata(item: watchlist_schema.WatchlistItemCreate, cached: models.MediaCache | None) -> dict:
    data = item.model_dump()
    if cached:
        for field in METADATA_FIELDS:
            value = getattr(cached, field)
            if metadata_missing(field, data[field]) and value is not None:
                data[field] = value
    return data


MAX_BATCH_SIZE = 100


@router.post("/batch", response_model=watchlist_schema.BatchImportResult)
async def batch_import_items(
    items: List[watchlist_schema.WatchlistItemCreate],
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(dependencies.get_current_user),
    db: AsyncSession = Depends(dependencies.get_db)
):
    """Import a batch and return a result for each submitted row."""
    if len(items) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Batch size {len(items)} exceeds maximum of {MAX_BATCH_SIZE}"
        )
    manual = [(item.title, item.mediaType, item.year) for item in items if item.tmdbId is None]
    linked = {item.tmdbId for item in items if item.tmdbId is not None}
    entry = models.WatchlistItem
    existing = await db.execute(
        select(func.lower(entry.title), entry.mediaType, entry.year, entry.tmdbId)
        .where(entry.userId == current_user.id, or_(
            entry.tmdbId.in_(linked),
            entry.tmdbId.is_(None) & func.lower(entry.title).in_({title.lower() for title, _, _ in manual}),
        ))
    )
    keys = {
        (kind, provider_id) if provider_id is not None else (kind, title, year)
        for title, kind, year, provider_id in existing
    }
    cache = await get_cached_bulk(db, manual)
    rows: list[dict] = []
    pending: dict[str, tuple[int, watchlist_schema.WatchlistItemCreate]] = {}
    results = ["duplicate"] * len(items)

    for index, item in enumerate(items):
        key = (item.mediaType, item.tmdbId) if item.tmdbId is not None else (
            item.mediaType, item.title.lower(), item.year
        )
        if key in keys:
            continue
        keys.add(key)
        item_id = str(uuid.uuid4())
        item_data = with_cached_metadata(item, cache.get((item.title, item.mediaType, item.year)) if item.tmdbId is None else None)
        rows.append({"id": item_id, "userId": current_user.id, **item_data})
        pending[item_id] = (index, item)

    inserted_ids = []
    if rows:
        stmt = pg_insert(entry).values(rows).on_conflict_do_nothing().returning(entry.id)
        inserted_ids = list((await db.execute(stmt)).scalars())
        await db.commit()

    for item_id in inserted_ids:
        index, item = pending[item_id]
        results[index] = "imported"
        if item.tmdbId is None and not item.coverUrl:
            background_tasks.add_task(_background_enrich, item.title, item.mediaType, item.year, item_id)
    imported = len(inserted_ids)
    return {"success": True, "imported": imported, "skipped": len(items) - imported, "results": results}


@router.patch(
    "/{item_id}/toggle-favorite",
    response_model=watchlist_schema.FavoriteToggleResult,
)
async def toggle_favorite(
    item_id: str,
    current_user: models.User = Depends(dependencies.get_current_user),
    db: AsyncSession = Depends(dependencies.get_db),
):
    result = await db.execute(
        select(models.WatchlistItem).filter(
            models.WatchlistItem.id == item_id,
            models.WatchlistItem.userId == current_user.id,
        )
    )
    db_item = result.scalars().first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Watchlist item not found")

    db_item.favorite = not db_item.favorite
    await db.commit()
    await db.refresh(db_item)
    return {"id": db_item.id, "favorite": db_item.favorite}


# Mirrors WatchlistItemUpdate. Previously listed 12 fields that don't exist on
# the model at all (poster_path, rating, tags, priority, watched_at, …), which
# implied a schema that was never real.
ALLOWED_UPDATE_FIELDS = {
    "title", "status", "favorite", "genres", "notes", "description",
    "year", "endYear", "running", "coverUrl", "runtime",
}

@router.patch("/{item_id}", response_model=watchlist_schema.WatchlistItem)
async def update_watchlist_item(
    item_id: str,
    item_in: watchlist_schema.WatchlistItemUpdate,
    current_user: models.User = Depends(dependencies.get_current_user),
    db: AsyncSession = Depends(dependencies.get_db)
):
    result = await db.execute(select(models.WatchlistItem).filter(models.WatchlistItem.id == item_id, models.WatchlistItem.userId == current_user.id))
    db_item = result.scalars().first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Watchlist item not found")

    update_data = item_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field in ALLOWED_UPDATE_FIELDS:
            setattr(db_item, field, value)

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Item already exists in your watchlist")
    await db.refresh(db_item)
    return db_item

@router.delete("/{item_id}", response_model=watchlist_schema.DeleteResult)
async def delete_watchlist_item(
    item_id: str,
    current_user: models.User = Depends(dependencies.get_current_user),
    db: AsyncSession = Depends(dependencies.get_db)
):
    result = await db.execute(select(models.WatchlistItem).filter(models.WatchlistItem.id == item_id, models.WatchlistItem.userId == current_user.id))
    db_item = result.scalars().first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Watchlist item not found")

    await db.delete(db_item)
    await db.commit()
    return {"ok": True}
