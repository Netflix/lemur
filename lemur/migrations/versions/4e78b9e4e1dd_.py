"""Add dns_provider id column to certificates table

Revision ID: 4e78b9e4e1dd
Revises: 3adfdd6598df
Create Date: 2018-04-10 14:00:30.701669

"""

# revision identifiers, used by Alembic.
revision = '4e78b9e4e1dd'
down_revision = '3adfdd6598df'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('certificates', sa.Column('dns_provider_id', sa.Integer(), nullable=True))


def downgrade():
    op.drop_column('certificates', 'dns_provider_id')
