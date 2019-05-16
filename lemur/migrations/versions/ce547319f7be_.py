"""Add id column to certificate_notification_associations.

Revision ID: ce547319f7be
Revises: 5bc47fa7cac4
Create Date: 2018-02-23 11:00:02.150561

"""

# revision identifiers, used by Alembic.
revision = "ce547319f7be"
down_revision = "5bc47fa7cac4"

import sqlalchemy as sa

from alembic import op
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()

TABLE = "certificate_notification_associations"


def upgrade():
    print("Adding id column")
    op.add_column(
        TABLE, sa.Column("id", sa.Integer, primary_key=True, autoincrement=True)
    )
    db.session.commit()
    db.session.flush()


def downgrade():
    op.drop_column(TABLE, "id")
    db.session.commit()
    db.session.flush()
