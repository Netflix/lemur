"""Add csr to certificates table

Revision ID: 7ead443ba911
Revises: 6006c79b6011
Create Date: 2018-10-21 22:06:23.056906

"""

# revision identifiers, used by Alembic.
revision = "7ead443ba911"
down_revision = "6006c79b6011"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("certificates", sa.Column("csr", sa.TEXT(), nullable=True))


def downgrade():
    op.drop_column("certificates", "csr")
