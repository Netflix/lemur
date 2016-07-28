"""Ensures that certificate name is unique

Revision ID: 7f71c0cea31a
Revises: 29d8c8455c86
Create Date: 2016-07-28 09:39:12.736506

"""

# revision identifiers, used by Alembic.
revision = '7f71c0cea31a'
down_revision = '29d8c8455c86'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text


def upgrade():
    conn = op.get_bind()

    for id, body, chain in conn.execute(text('select id, body, chain from certificates')):
        if body and chain:
            stmt = text('update certificates set body=:body, chain=:chain where id=:id')
            stmt = stmt.bindparams(body=body.strip(), chain=chain.strip(), id=id)
        else:
            stmt = text('update certificates set body=:body where id=:id')
            stmt = stmt.bindparams(body=body.strip(), id=id)

        op.execute(stmt)

    op.create_unique_constraint(None, 'certificates', ['name'])


def downgrade():
    op.drop_constraint(None, 'certificates', type_='unique')
