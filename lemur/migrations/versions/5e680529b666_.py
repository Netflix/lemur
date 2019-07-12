"""Sync up endpoints properties

Revision ID: 5e680529b666
Revises: 131ec6accff5
Create Date: 2017-01-26 05:05:25.168125

"""

# revision identifiers, used by Alembic.
revision = "5e680529b666"
down_revision = "131ec6accff5"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("endpoints", sa.Column("sensitive", sa.Boolean(), nullable=True))
    op.add_column("endpoints", sa.Column("source_id", sa.Integer(), nullable=True))
    op.create_foreign_key(None, "endpoints", "sources", ["source_id"], ["id"])


def downgrade():
    op.drop_constraint(None, "endpoints", type_="foreignkey")
    op.drop_column("endpoints", "source_id")
    op.drop_column("endpoints", "sensitive")
