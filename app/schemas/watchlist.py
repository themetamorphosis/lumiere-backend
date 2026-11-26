from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Literal
from datetime import datetime

MediaType = Literal["movie", "tv", "anime"]
StatusType = Literal["watched", "pending", "wishlist"]


class WatchlistItemBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    mediaType: MediaType
    tmdbId: Optional[int] = Field(None, gt=0, le=9007199254740991)
    status: StatusType
    favorite: Optional[bool] = False
    genres: Optional[List[str]] = []
    notes: Optional[str] = Field(None, max_length=1000)
    description: Optional[str] = Field(None, max_length=2000)
    year: Optional[int] = None
    endYear: Optional[int] = None
    running: Optional[bool] = False
    coverUrl: Optional[str] = None
    runtime: Optional[int] = None


class WatchlistItemCreate(WatchlistItemBase):
    pass


class WatchlistItemUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)

    @field_validator("title")
    @classmethod
    def title_cannot_be_null(cls, title: Optional[str]) -> str:
        if title is None:
            raise ValueError("Title is required")
        return title
    status: Optional[StatusType] = None
    favorite: Optional[bool] = None
    genres: Optional[List[str]] = None
    notes: Optional[str] = Field(None, max_length=1000)
    description: Optional[str] = Field(None, max_length=2000)
    year: Optional[int] = None
    endYear: Optional[int] = None
    running: Optional[bool] = None
    coverUrl: Optional[str] = None
    runtime: Optional[int] = None


class WatchlistItem(WatchlistItemBase):
    id: str
    userId: str
    createdAt: Optional[datetime] = None
    updatedAt: Optional[datetime] = None

    class Config:
        from_attributes = True


# The three shapes below were documented by hand in CLAUDE.md and returned as
# bare dicts. Declaring them keeps the OpenAPI schema honest automatically.


class WatchlistPage(BaseModel):
    """`GET /watchlist` — a page of items plus its pagination envelope."""
    items: List[WatchlistItem]
    total: int
    limit: int
    offset: int
    has_more: bool


class BatchImportResult(BaseModel):
    """`POST /watchlist/batch`."""
    success: bool
    imported: int
    skipped: int
    results: List[Literal["imported", "duplicate"]]


class FavoriteToggleResult(BaseModel):
    """`PATCH /watchlist/{id}/toggle-favorite`."""
    id: str
    favorite: bool


class DeleteResult(BaseModel):
    """`DELETE /watchlist/{id}`."""
    ok: bool
