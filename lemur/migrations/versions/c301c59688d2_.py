"""

This database upgrade updates the key_type information for either
still valid or expired certificates in the last 30 days. For RSA
keys, the algorithm is determined based on the key length. For
the rest of the keys, the certificate body is parsed to determine
the exact key_type information.

Each individual DB change is explicitly committed, and the respective
log is added to a file configured in LOG_UPGRADE_FILE or, by default,
to a file named db_upgrade.log in the current working directory.
Any error encountered while parsing a certificate will
also be logged along with the certificate ID. If faced with any issue
while running this upgrade, there is no harm in re-running the upgrade.
Each run processes only rows for which key_type information is not yet
determined.

A successful complete run will end up updating the Alembic Version to
the new Revision ID c301c59688d2. Currently, Lemur supports only RSA
and ECC certificates. This could be a long-running job depending upon
the number of DB entries it may process.

Revision ID: c301c59688d2
Revises: 434c29e40511
Create Date: 2020-09-21 14:28:50.757998

"""

# revision identifiers, used by Alembic.
revision = "c301c59688d2"
down_revision = "434c29e40511"

from alembic import op
from sqlalchemy.sql import text
import time
import datetime
from flask import current_app

from logging import Formatter, FileHandler, getLogger

from lemur.common import utils

log = getLogger(__name__)
handler = FileHandler(current_app.config.get("LOG_UPGRADE_FILE", "db_upgrade.log"))
handler.setFormatter(
    Formatter("%(asctime)s %(levelname)s: %(message)s " "[in %(pathname)s:%(lineno)d]")
)
handler.setLevel(current_app.config.get("LOG_LEVEL", "DEBUG"))
log.setLevel(current_app.config.get("LOG_LEVEL", "DEBUG"))
log.addHandler(handler)


def upgrade():
    log.info("\n*** Starting new run(%s) ***\n" % datetime.datetime.now())
    start_time = time.time()

    # Update RSA keys using the key length information
    update_key_type_rsa(1024)
    update_key_type_rsa(2048)
    update_key_type_rsa(4096)

    # Process remaining certificates. Though below method does not make any assumptions, most of the remaining ones should be ECC certs.
    update_key_type()

    log.info("--- Total %s seconds ---\n" % (time.time() - start_time))


def downgrade():
    # Change key type column back to null
    # Going back 32 days instead of 31 to make sure no certificates are skipped
    stmt = text(
        "update certificates set key_type=null where not_after > CURRENT_DATE - 32"
    )
    op.execute(stmt)
    commit()


"""
    Helper methods performing updates for RSA and rest of the keys
"""


def update_key_type_rsa(bits):
    log.info("Processing certificate with key type RSA %s\n" % bits)

    stmt = text(
        f"update certificates set key_type='RSA{bits}' where bits={bits} and not_after > CURRENT_DATE - 31 and key_type is null"
    )
    log.info("Query: %s\n" % stmt)

    start_time = time.time()
    op.execute(stmt)
    commit()

    log.info("--- %s seconds ---\n" % (time.time() - start_time))


def update_key_type():
    conn = op.get_bind()
    start_time = time.time()

    # Loop through all certificates that are valid today or expired in the last 30 days.
    for cert_id, body in conn.execute(
        text(
            "select id, body from certificates where not_after > CURRENT_DATE - 31 and key_type is null"
        )
    ):
        try:
            cert_key_type = utils.get_key_type_from_certificate(body)
        except ValueError as e:
            log.error(
                "Error in processing certificate - ID: %s Error: %s \n"
                % (cert_id, str(e))
            )
        else:
            log.info(
                "Processing certificate - ID: %s key_type: %s\n"
                % (cert_id, cert_key_type)
            )
            stmt = text("update certificates set key_type=:key_type where id=:id")
            stmt = stmt.bindparams(key_type=cert_key_type, id=cert_id)
            op.execute(stmt)

            commit()

    log.info("--- %s seconds ---\n" % (time.time() - start_time))


def commit():
    stmt = text("commit")
    op.execute(stmt)
