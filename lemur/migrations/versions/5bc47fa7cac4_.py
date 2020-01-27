"""add third party roles to lemur

Revision ID: 5bc47fa7cac4
Revises: c05a8998b371
Create Date: 2017-12-08 14:19:11.903864

"""

# revision identifiers, used by Alembic.
revision = "5bc47fa7cac4"
down_revision = "c05a8998b371"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        "roles", sa.Column("third_party", sa.Boolean(), nullable=True, default=False)
    )


def downgrade():
    op.drop_column("roles", "third_party")
