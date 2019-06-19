"""Convert pending cert status field to text

Revision ID: 5ae0ecefb01f
Revises: 1db4f82bc780
Create Date: 2018-08-14 08:16:43.329316

"""

# revision identifiers, used by Alembic.
revision = "5ae0ecefb01f"
down_revision = "1db4f82bc780"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column(
        table_name="pending_certs", column_name="status", nullable=True, type_=sa.TEXT()
    )


def downgrade():
    op.alter_column(
        table_name="pending_certs",
        column_name="status",
        nullable=True,
        type_=sa.VARCHAR(128),
    )
