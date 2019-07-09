"""Modifies the unique index for the certificate replacements

Revision ID: 8ae67285ff14
Revises: 5e680529b666
Create Date: 2017-05-10 11:56:13.999332

"""

# revision identifiers, used by Alembic.
revision = "8ae67285ff14"
down_revision = "5e680529b666"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_index("certificate_replacement_associations_ix")
    op.create_index(
        "certificate_replacement_associations_ix",
        "certificate_replacement_associations",
        ["replaced_certificate_id", "certificate_id"],
        unique=True,
    )


def downgrade():
    op.drop_index("certificate_replacement_associations_ix")
    op.create_index(
        "certificate_replacement_associations_ix",
        "certificate_replacement_associations",
        ["certificate_id", "certificate_id"],
        unique=True,
    )
