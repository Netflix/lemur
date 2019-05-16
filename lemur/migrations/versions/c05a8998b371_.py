"""Adds JWT Tokens to Users

Revision ID: c05a8998b371
Revises: ac483cfeb230
Create Date: 2017-11-10 14:51:28.975927

"""

# revision identifiers, used by Alembic.
revision = "c05a8998b371"
down_revision = "ac483cfeb230"

from alembic import op
import sqlalchemy as sa
import sqlalchemy_utils


def upgrade():
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("ttl", sa.BigInteger(), nullable=False),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("api_keys")
