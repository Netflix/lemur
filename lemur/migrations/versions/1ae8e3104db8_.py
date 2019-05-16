"""Adds additional ENUM for creating and updating certificates.

Revision ID: 1ae8e3104db8
Revises: a02a678ddc25
Create Date: 2017-07-13 12:32:09.162800

"""

# revision identifiers, used by Alembic.
revision = "1ae8e3104db8"
down_revision = "a02a678ddc25"

from alembic import op


def upgrade():
    op.sync_enum_values(
        "public", "log_type", ["key_view"], ["create_cert", "key_view", "update_cert"]
    )


def downgrade():
    op.sync_enum_values(
        "public", "log_type", ["create_cert", "key_view", "update_cert"], ["key_view"]
    )
