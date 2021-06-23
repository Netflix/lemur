"""This Database upgrade will make the domains table unique and is required fro future versions of Lemur.

Revision ID: 614f0f51b553
Revises: 4fe230f7a26e
Create Date: 2021-06-22 23:22:30.078483

"""

# revision identifiers, used by Alembic.
revision = '614f0f51b553'
down_revision = '4fe230f7a26e'

import datetime
import time
from logging import Formatter, FileHandler, getLogger

from alembic import op
from flask import current_app
from sqlalchemy.sql import text

log = getLogger(__name__)
handler = FileHandler(current_app.config.get("LOG_UPGRADE_FILE", "db_upgrade.log"))
handler.setFormatter(
    Formatter(
        "%(asctime)s %(levelname)s: %(message)s " "[in %(pathname)s:%(lineno)d]"
    )
)
handler.setLevel(current_app.config.get("LOG_LEVEL", "DEBUG"))
log.setLevel(current_app.config.get("LOG_LEVEL", "DEBUG"))
log.addHandler(handler)


def upgrade():
    log.info("\n*** Starting DB upgrade(%s) ***\n" % datetime.datetime.now())
    start_time = time.time()

    # Do Upgrade
    dedup_domains_table()

    log.info("---Upgrade Complete - Total %s seconds ---\n" % (time.time() - start_time))


def downgrade():
    log.info("\n*** Request to downgrade at (%s) ***\n" % datetime.datetime.now())
    log.info("It is not possible to downgrade this change since duplicated domains were already deleted.")
    log.info("If you need to restore the duplicated domains for some reason, you will need to restore from backup.")


def dedup_domains_table():
    conn = op.get_bind()

    # Loop through all domains and get a list of them by count
    for name, count in conn.execute(text(
            "SELECT name,count(*) FROM domains GROUP BY name HAVING COUNT(*) > 1 ORDER BY count(*) DESC")):

        # Find all duplicates for each domain.
        id = False
        sensitive = False
        for cur_id, _, cur_sensitive in conn.execute(text(
                f"SELECT id, name, sensitive FROM domains WHERE name = {name} ORDER BY id ASC")):

            #  Keep only the first one (lowest id number), and update the rest
            if id == False:
                id = cur_id
                sensitive = cur_sensitive
            else:
                if sensitive != cur_sensitive:
                    log.error(
                        f"Error in domain deduplication. {name} has conflicting sensitivities in domains table.  Fix these and run again.")
                    return

                # Update association to point to single domain entry
                conn.execute(
                    text(
                        f"UPDATE certificate_associations SET domain_id = {id} WHERE domain_id = {cur_id}"
                    )
                )
                # Delete current domain entry
                conn.execute(
                    text(
                        f"DELETE FROM domains WHERE id = {cur_id}"
                    )
                )
    # Update the Schema so the domains table has unique names
    conn.execute(
        text(
            "ALTER TABLE domains ADD UNIQUE(name)"
        )
    )
