"""Add pg_trgm indexes on certain attributes used for CN / Name filtering in ILIKE queries.

Revision ID: ee827d1e1974
Revises: 7ead443ba911
Create Date: 2018-11-05 09:49:40.226368

"""

# revision identifiers, used by Alembic.
revision = "ee827d1e1974"
down_revision = "7ead443ba911"

from alembic import op
from sqlalchemy.exc import ProgrammingError


def upgrade():
    connection = op.get_bind()
    connection.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    op.create_index(
        "ix_certificates_cn",
        "certificates",
        ["cn"],
        unique=False,
        postgresql_ops={"cn": "gin_trgm_ops"},
        postgresql_using="gin",
    )
    op.create_index(
        "ix_certificates_name",
        "certificates",
        ["name"],
        unique=False,
        postgresql_ops={"name": "gin_trgm_ops"},
        postgresql_using="gin",
    )
    op.create_index(
        "ix_domains_name_gin",
        "domains",
        ["name"],
        unique=False,
        postgresql_ops={"name": "gin_trgm_ops"},
        postgresql_using="gin",
    )


def downgrade():
    op.drop_index("ix_domains_name", table_name="domains")
    op.drop_index("ix_certificates_name", table_name="certificates")
    op.drop_index("ix_certificates_cn", table_name="certificates")
