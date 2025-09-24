"""Add column application_name to api_keys table. Null values are allowed.

Revision ID: e2d406ada25c
Revises: 189e5fda5bf8
Create Date: 2021-11-24 14:48:18.747487

"""

# revision identifiers, used by Alembic.
revision = "e2d406ada25c"
down_revision = "189e5fda5bf8"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        "api_keys", sa.Column("application_name", sa.String(256), nullable=True)
    )


def downgrade():
    op.drop_column("api_keys", "application_name")
