"""Adds additional ENUM for creating and updating certificates.

Revision ID: 1ae8e3104db8
Revises: a02a678ddc25
Create Date: 2017-07-13 12:32:09.162800

"""

# revision identifiers, used by Alembic.
revision = '1ae8e3104db8'
down_revision = 'a02a678ddc25'

from alembic import op


def upgrade():
    connection = None

    if not op.get_context().as_sql:
        connection = op.get_bind()
        connection.execution_options(isolation_level='AUTOCOMMIT')

    op.execute("ALTER TYPE log_type ADD VALUE 'create_cert'")
    op.execute("ALTER TYPE log_type ADD VALUE 'update_cert'")

    if connection is not None:
        connection.execution_options(isolation_level='READ_COMMITTED')


def downgrade():
    connection = None

    if not op.get_context().as_sql:
        connection = op.get_bind()
        connection.execution_options(isolation_level='AUTOCOMMIT')

    op.execute("ALTER TYPE log_type DROP VALUE 'create_cert'")
    op.execute("ALTER TYPE log_type DROP VALUE 'update_cert'")

    if connection is not None:
        connection.execution_options(isolation_level='READ_COMMITTED')
