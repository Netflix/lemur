"""Add default rotation_policy to certs where it's missing

Revision ID: 1db4f82bc780
Revises: 3adfdd6598df
Create Date: 2018-08-03 12:56:44.565230

"""

# revision identifiers, used by Alembic.
revision = "1db4f82bc780"
down_revision = "3adfdd6598df"

from alembic import op

from flask import current_app
from logging import Formatter, FileHandler, getLogger

log = getLogger(__name__)
handler = FileHandler(current_app.config.get("LOG_UPGRADE_FILE", "db_upgrade.log"))
handler.setFormatter(
    Formatter("%(asctime)s %(levelname)s: %(message)s " "[in %(pathname)s:%(lineno)d]")
)
handler.setLevel(current_app.config.get("LOG_LEVEL", "DEBUG"))
log.setLevel(current_app.config.get("LOG_LEVEL", "DEBUG"))
log.addHandler(handler)


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
