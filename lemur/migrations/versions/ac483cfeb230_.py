"""empty message

Revision ID: ac483cfeb230
Revises: b29e2c4bf8c9
Create Date: 2017-10-11 10:16:39.682591

"""

# revision identifiers, used by Alembic.
revision = "ac483cfeb230"
down_revision = "b29e2c4bf8c9"

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


def upgrade():
    op.alter_column(
        "certificates",
        "name",
        existing_type=sa.VARCHAR(length=128),
        type_=sa.String(length=256),
    )


def downgrade():
    op.alter_column(
        "certificates",
        "name",
        existing_type=sa.VARCHAR(length=256),
        type_=sa.String(length=128),
    )
