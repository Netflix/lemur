"""Add 'ports' column to certificate_associations table

Revision ID: 4fe230f7a26e
Revises: c301c59688d2
Create Date: 2021-05-07 10:57:16.964743

"""

# revision identifiers, used by Alembic.
revision = '4fe230f7a26e'
down_revision = 'c301c59688d2'

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


def upgrade():
    # Add the "ports" column
    op.add_column('certificate_associations', sa.Column('ports', postgresql.ARRAY(sa.Integer()), nullable=True))
    # Make the existing foreign key columns non-nullable
    op.alter_column('certificate_associations', 'domain_id',
                    existing_type=sa.INTEGER(),
                    nullable=False)
    op.alter_column('certificate_associations', 'certificate_id',
                    existing_type=sa.INTEGER(),
                    nullable=False)


def downgrade():
    # Make the existing foreign key columns nullable
    op.alter_column('certificate_associations', 'certificate_id',
                    existing_type=sa.INTEGER(),
                    nullable=True)
    op.alter_column('certificate_associations', 'domain_id',
                    existing_type=sa.INTEGER(),
                    nullable=True)
    # Drop the "ports" column
    op.drop_column('certificate_associations', 'ports')
