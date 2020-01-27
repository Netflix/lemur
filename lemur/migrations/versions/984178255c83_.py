"""Add status to pending certificate, and store resolved cert id

Revision ID: 984178255c83
Revises: f2383bf08fbc
Create Date: 2018-10-11 20:49:12.704563

"""

# revision identifiers, used by Alembic.
revision = "984178255c83"
down_revision = "f2383bf08fbc"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("pending_certs", sa.Column("resolved", sa.Boolean(), nullable=True))
    op.add_column(
        "pending_certs", sa.Column("resolved_cert_id", sa.Integer(), nullable=True)
    )


def downgrade():
    op.drop_column("pending_certs", "resolved_cert_id")
    op.drop_column("pending_certs", "resolved")
