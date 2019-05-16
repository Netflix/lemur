"""Ensures that certificate name is unique.
If duplicates are found, we follow the standard naming convention of appending '-X'
with x being the number of duplicates starting at 1.

Revision ID: 7f71c0cea31a
Revises: 29d8c8455c86
Create Date: 2016-07-28 09:39:12.736506

"""

# revision identifiers, used by Alembic.
revision = "7f71c0cea31a"
down_revision = "29d8c8455c86"

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text


def upgrade():
    conn = op.get_bind()
    for name in conn.execute(
        text("select name from certificates group by name having count(*) > 1")
    ):
        for idx, id in enumerate(
            conn.execute(
                text(
                    "select id from certificates where certificates.name like :name order by id ASC"
                ).bindparams(name=name[0])
            )
        ):
            if not idx:
                continue
            new_name = name[0] + "-" + str(idx)
            stmt = text("update certificates set name=:name where id=:id")
            stmt = stmt.bindparams(name=new_name, id=id[0])
            op.execute(stmt)

    op.create_unique_constraint(None, "certificates", ["name"])


def downgrade():
    op.drop_constraint(None, "certificates", type_="unique")
