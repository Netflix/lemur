"""Add new Indexes for faster searching

Revision ID: 3097d57f3f0b
Revises: 4fe230f7a26e
Create Date: 2021-06-19 20:18:55.332165

"""

# revision identifiers, used by Alembic.
revision = "3097d57f3f0b"
down_revision = "4fe230f7a26e"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_index(
        "ix_root_authority_id",
        "certificates",
        ["root_authority_id"],
        unique=False,
        postgresql_where=sa.text("root_authority_id IS NOT NULL"),
    )
    op.create_index(
        "certificate_associations_certificate_id_idx",
        "certificate_associations",
        ["certificate_id"],
        unique=False,
    )
    op.create_index("ix_certificates_serial", "certificates", ["serial"], unique=False)


def downgrade():
    op.drop_index("ix_root_authority_id", table_name="certificates")
    op.drop_index(
        "certificate_associations_certificate_id_idx",
        table_name="certificate_associations",
    )
    op.drop_index("ix_certificates_serial", table_name="certificates")
