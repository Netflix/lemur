"""Create an index on the domains table for the domain name
Revision ID: c87cb989af04
Revises: 9392b9f9a805
Create Date: 2018-10-11 09:44:57.099854

"""

revision = "c87cb989af04"
down_revision = "9392b9f9a805"

from alembic import op


def upgrade():
    op.create_index(op.f("ix_domains_name"), "domains", ["name"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_domains_name"), table_name="domains")
