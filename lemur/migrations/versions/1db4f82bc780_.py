"""Add default rotation_policy to certs where it's missing

Revision ID: 1db4f82bc780
Revises: 3adfdd6598df
Create Date: 2018-08-03 12:56:44.565230

"""

# revision identifiers, used by Alembic.
revision = "1db4f82bc780"
down_revision = "3adfdd6598df"

import logging

from alembic import op

log = logging.getLogger(__name__)


def upgrade():
    connection = op.get_bind()

    result = connection.execute(
        """\
       UPDATE certificates
           SET rotation_policy_id=(SELECT id FROM rotation_policies WHERE name='default')
         WHERE rotation_policy_id IS NULL
        RETURNING id
    """
    )
    log.info("Filled rotation_policy for %d certificates" % result.rowcount)


def downgrade():
    pass
