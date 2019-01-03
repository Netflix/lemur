"""empty message

Revision ID: 9f79024fe67b
Revises: ee827d1e1974
Create Date: 2019-01-03 15:36:59.181911

"""

# revision identifiers, used by Alembic.
revision = '9f79024fe67b'
down_revision = 'ee827d1e1974'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.sync_enum_values('public', 'log_type',
                        ['key_view', 'create_cert', 'update_cert', 'revoke_cert'],
                        ['key_view', 'create_cert', 'update_cert', 'revoke_cert', 'delete_cert'])


def downgrade():
    op.sync_enum_values('public', 'log_type',
                        ['key_view', 'create_cert', 'update_cert', 'revoke_cert', 'delete_cert'],
                        ['key_view', 'create_cert', 'update_cert', 'revoke_cert'])
