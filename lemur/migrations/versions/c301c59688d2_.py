"""

This upgrade of database updates the key_type information for certificates
that are either still valid or have expired in last 30 days. For RSA keys,
the algorithm is determined based on the key length. For rest of the keys,
the certificate body is parsed to determine the exact key type information.

Each individual change is explicitly committed. The logs are added to file
named upgrade_logs in current working directory. If faced any issue while
running this upgrade, there is no harm in re-running the upgrade. Each run
processes only the keys for which key type information is not yet determined.
A successful end to end run will end up updating the Alembic Version to new
Revision ID c301c59688d2. Currently only RSA and ECC certificates are supported
by Lemur. This could be a long running job depending upon the number of
keys it may process.

Revision ID: c301c59688d2
Revises: 434c29e40511
Create Date: 2020-09-21 14:28:50.757998

"""

# revision identifiers, used by Alembic.
revision = 'c301c59688d2'
down_revision = '434c29e40511'

from alembic import op
from sqlalchemy.sql import text
from lemur.common import utils
import time
import datetime

log_file = open('db_upgrade.log', 'a')


def upgrade():
    log_file.write("\n*** Starting new run(%s) ***\n" % datetime.datetime.now())
    start_time = time.time()

    # Update RSA keys using the key length information
    update_key_type_rsa(1024)
    update_key_type_rsa(2048)
    update_key_type_rsa(4096)

    # Process remaining certificates. Though below method does not make any assumptions, most of the remaining ones should be ECC certs.
    update_key_type()

    log_file.write("--- Total %s seconds ---\n" % (time.time() - start_time))
    log_file.close()


def downgrade():
    # Change key type column back to null
    # Going back 32 days instead of 31 to make sure no certificates are skipped
    stmt = text(
        "update certificates set key_type=null where not_after > CURRENT_DATE - 32"
    )
    op.execute(stmt)


"""
    Helper methods performing updates for RSA and rest of the keys
"""


def update_key_type_rsa(bits):
    log_file.write("Processing certificate with key type RSA %s\n" % bits)

    stmt = text(
        "update certificates set key_type='RSA{0}' where bits={0} and not_after > CURRENT_DATE - 31 and key_type is null".format(bits)
    )
    log_file.write("Query: %s\n" % stmt)

    start_time = time.time()
    op.execute(stmt)
    commit()

    log_file.write("--- %s seconds ---\n" % (time.time() - start_time))


def update_key_type():
    conn = op.get_bind()
    start_time = time.time()

    # Loop through all certificates are valid today or expired in last 30 days
    for cert_id, body in conn.execute(
            text(
                "select id, body from certificates where bits < 1024 and not_after > CURRENT_DATE - 31 and key_type is null")
    ):
        try:
            cert_key_type = utils.get_key_type_from_certificate(body)
        except ValueError:
            log_file.write("Error in processing certificate. ID: %s\n" % cert_id)
        else:
            log_file.write("Processing certificate - ID: %s key_type: %s\n" % (cert_id, cert_key_type))
            stmt = text(
                "update certificates set key_type=:key_type where id=:id"
            )
            stmt = stmt.bindparams(key_type=cert_key_type, id=cert_id)
            op.execute(stmt)

            commit()

    log_file.write("--- %s seconds ---\n" % (time.time() - start_time))


def commit():
    stmt = text("commit")
    op.execute(stmt)
