"""Create dns_providers table

Revision ID: 3adfdd6598df
Revises: 556ceb3e3c3e
Create Date: 2018-04-10 13:25:47.007556

"""

# revision identifiers, used by Alembic.
revision = '3adfdd6598df'
down_revision = '556ceb3e3c3e'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

from sqlalchemy_utils import ArrowType


def upgrade():
    # create provider table
    op.create_table(
        'dns_providers',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=256), nullable=True),
        sa.Column('description', sa.String(length=1024), nullable=True),
        sa.Column('provider_type', sa.String(length=256), nullable=True),
        sa.Column('credentials', sa.String(length=256), nullable=True),
        sa.Column('api_endpoint', sa.String(length=256), nullable=True),
        sa.Column('date_created', ArrowType(), server_default=sa.text('now()'), nullable=False),
        sa.Column('status', sa.String(length=128), nullable=True),
        sa.Column('options', JSON),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )


def downgrade():
    op.drop_table('dns_providers')
