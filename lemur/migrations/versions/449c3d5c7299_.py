"""Add unique constraint to certificate_notification_associations table.

Revision ID: 449c3d5c7299
Revises: 5770674184de
Create Date: 2018-02-24 22:51:35.369229

"""

# revision identifiers, used by Alembic.
revision = '449c3d5c7299'
down_revision = '5770674184de'

from alembic import op
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

CONSTRAINT_NAME = "uq_dest_not_ids"
TABLE = "certificate_notification_associations"
COLUMNS = ["notification_id", "certificate_id"]


def upgrade():
    connection = op.get_bind()
    # Delete duplicate entries
    connection.execute("""\
        DELETE FROM certificate_notification_associations WHERE ctid NOT IN (
            -- Select the first tuple ID for each (notification_id, certificate_id) combination and keep that
            SELECT min(ctid) FROM certificate_notification_associations GROUP BY notification_id, certificate_id
        )
    """)
    op.create_unique_constraint(CONSTRAINT_NAME, TABLE, COLUMNS)


def downgrade():
    op.drop_constraint(CONSTRAINT_NAME, TABLE)
