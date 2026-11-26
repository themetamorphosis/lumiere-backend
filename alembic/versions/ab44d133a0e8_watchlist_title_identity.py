"""Track catalogue IDs and retain separate editions of the same title."""
import sqlalchemy as sa
from alembic import op

revision = "ab44d133a0e8"
down_revision = "1ccf7baa31f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("WatchlistItem", sa.Column("tmdbId", sa.BigInteger(), nullable=True))
    op.create_index(
        "ix_watchlistitem_catalogue_identity", "WatchlistItem", ["userId", "mediaType", "tmdbId"],
        unique=True,
    )
    op.create_index(
        "ix_watchlistitem_manual_identity", "WatchlistItem", ["userId", "mediaType", "title", "year"],
        unique=True, postgresql_where=sa.text('"tmdbId" IS NULL'), postgresql_nulls_not_distinct=True,
    )
    op.drop_constraint("watchlistitem_userid_title_mediatype_key", "WatchlistItem", type_="unique")


def downgrade() -> None:
    # PostgreSQL refuses this downgrade if it would discard new editions.
    op.create_unique_constraint(
        "watchlistitem_userid_title_mediatype_key", "WatchlistItem", ["userId", "title", "mediaType"],
    )
    op.drop_index("ix_watchlistitem_manual_identity", table_name="WatchlistItem")
    op.drop_index("ix_watchlistitem_catalogue_identity", table_name="WatchlistItem")
    op.drop_column("WatchlistItem", "tmdbId")
