"""Add lowercase index for certificate name and cn and also for domain name

Revision ID: 8323a5ea723a
Revises: b33c838cb669
Create Date: 2020-01-10 10:51:44.776052

"""

# revision identifiers, used by Alembic.
revision = "8323a5ea723a"
down_revision = "b33c838cb669"

from alembic import op
from sqlalchemy import text

import sqlalchemy as sa


def upgrade():
    op.create_index(
        "ix_certificates_cn_lower",
        "certificates",
        [text("lower(cn)")],
        unique=False,
        postgresql_ops={"lower(cn)": "gin_trgm_ops"},
        postgresql_using="gin",
    )
    op.create_index(
        "ix_certificates_name_lower",
        "certificates",
        [text("lower(name)")],
        unique=False,
        postgresql_ops={"lower(name)": "gin_trgm_ops"},
        postgresql_using="gin",
    )
    op.create_index(
        "ix_domains_name_lower",
        "domains",
        [text("lower(name)")],
        unique=False,
        postgresql_ops={"lower(name)": "gin_trgm_ops"},
        postgresql_using="gin",
    )


def downgrade():
    op.drop_index("ix_certificates_cn_lower", table_name="certificates")
    op.drop_index("ix_certificates_name_lower", table_name="certificates")
    op.drop_index("ix_domains_name_lower", table_name="domains")
