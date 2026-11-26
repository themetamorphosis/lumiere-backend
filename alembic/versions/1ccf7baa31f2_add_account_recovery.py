"""Add session revocation and password recovery state."""
from alembic import op
import sqlalchemy as sa

revision = "1ccf7baa31f2"
down_revision = "c7e1f4a92d13"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("User", sa.Column("auth_version", sa.String(), nullable=True))
    op.add_column("User", sa.Column("reset_token_digest", sa.String(64), nullable=True))
    op.add_column("User", sa.Column("reset_token_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_User_reset_token_digest", "User", ["reset_token_digest"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_User_reset_token_digest", table_name="User")
    op.drop_column("User", "reset_token_expires_at")
    op.drop_column("User", "reset_token_digest")
    op.drop_column("User", "auth_version")
