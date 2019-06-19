"""Create index on certificates table for id desc


Revision ID: f2383bf08fbc
Revises: c87cb989af04
Create Date: 2018-10-11 11:23:31.195471

"""

revision = "f2383bf08fbc"
down_revision = "c87cb989af04"

import sqlalchemy as sa
from alembic import op


def upgrade():
    op.create_index(
        "ix_certificates_id_desc",
        "certificates",
        [sa.text("id DESC")],
        unique=True,
        postgresql_using="btree",
    )


def downgrade():
    op.drop_index("ix_certificates_id_desc", table_name="certificates")
