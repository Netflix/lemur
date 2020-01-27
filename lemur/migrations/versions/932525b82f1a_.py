"""Changing the column name to the more accurately named 'notify'.

Revision ID: 932525b82f1a
Revises: 7f71c0cea31a
Create Date: 2016-10-13 20:14:33.928029

"""

# revision identifiers, used by Alembic.
revision = "932525b82f1a"
down_revision = "7f71c0cea31a"

from alembic import op


def upgrade():
    op.alter_column("certificates", "active", new_column_name="notify")


def downgrade():
    op.alter_column("certificates", "notify", new_column_name="active")
