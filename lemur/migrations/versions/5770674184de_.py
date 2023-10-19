"""Remove duplicates from certificate_notification_associations.

Revision ID: 5770674184de
Revises: ce547319f7be
Create Date: 2018-02-23 15:27:30.335435

"""

# revision identifiers, used by Alembic.
revision = "5770674184de"
down_revision = "ce547319f7be"

from flask_sqlalchemy import SQLAlchemy
from lemur.models import certificate_notification_associations

db = SQLAlchemy()
session = db.session()


def upgrade():
    print("Querying for all entries in certificate_notification_associations.")
    # Query for all entries in table
    results = session.query(certificate_notification_associations).with_entities(
        certificate_notification_associations.c.certificate_id,
        certificate_notification_associations.c.notification_id,
        certificate_notification_associations.c.id,
    )

    seen = {}
    # Iterate through all entries and mark as seen for each certificate_id and notification_id pair
    for x in results:
        # If we've seen a pair already, delete the duplicates
        if seen.get(f"{x.certificate_id}-{x.notification_id}"):
            print(f"Deleting duplicate: {x}")
            d = session.query(certificate_notification_associations).filter(
                certificate_notification_associations.c.id == x.id
            )
            d.delete(synchronize_session=False)
        seen[f"{x.certificate_id}-{x.notification_id}"] = True
    db.session.commit()
    db.session.flush()


def downgrade():
    # No way to downgrade this
    pass
