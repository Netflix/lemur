"""Add last_updated field to Pending Certs
Revision ID: 9392b9f9a805
Revises: 5ae0ecefb01f
Create Date: 2018-09-17 08:33:37.087488

"""

# revision identifiers, used by Alembic.
revision = "9392b9f9a805"
down_revision = "5ae0ecefb01f"

from alembic import op
from sqlalchemy_utils import ArrowType
import sqlalchemy as sa


def upgrade():
    op.add_column(
        "pending_certs",
        sa.Column(
            "last_updated",
            ArrowType,
            server_default=sa.text("now()"),
            onupdate=sa.text("now()"),
            nullable=False,
        ),
    )


def downgrade():
    op.drop_column("pending_certs", "last_updated")
