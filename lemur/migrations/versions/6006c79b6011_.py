"""Add unique constraint to label column on sources table

Revision ID: 6006c79b6011
Revises: 984178255c83
Create Date: 2018-10-19 15:23:06.750510

"""

# revision identifiers, used by Alembic.
revision = "6006c79b6011"
down_revision = "984178255c83"

from alembic import op


def upgrade():
    op.create_unique_constraint("uq_label", "sources", ["label"])


def downgrade():
    op.drop_constraint("uq_label", "sources", type_="unique")
