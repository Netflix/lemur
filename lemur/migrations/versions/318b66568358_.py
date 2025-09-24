"""Set 'deleted' flag from null to false on all certificates once

Revision ID: 318b66568358
Revises: 9f79024fe67b
Create Date: 2019-02-05 15:42:25.477587

"""

# revision identifiers, used by Alembic.
revision = "318b66568358"
down_revision = "9f79024fe67b"

from alembic import op


def upgrade():
    connection = op.get_bind()
    # Delete duplicate entries
    connection.execute("UPDATE certificates SET deleted = false WHERE deleted IS NULL")


def downgrade():
    pass
