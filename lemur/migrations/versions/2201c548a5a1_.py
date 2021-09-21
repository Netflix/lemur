"""empty message

Revision ID: 2201c548a5a1
Revises: 3097d57f3f0b
Create Date: 2021-09-20 17:34:05.847067

"""

# revision identifiers, used by Alembic.
revision = '2201c548a5a1'
down_revision = '3097d57f3f0b'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('endpoints', sa.Column('certificate_path', sa.String(length=256), nullable=True))
    op.add_column('endpoints', sa.Column('registry_type', sa.String(length=128), nullable=True))


def downgrade():
    op.drop_column('endpoints', 'registry_type')
    op.drop_column('endpoints', 'certificate_path')
