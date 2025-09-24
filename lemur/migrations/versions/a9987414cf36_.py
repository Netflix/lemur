"""empty message

Revision ID: a9987414cf36
Revises: e2d406ada25c
Create Date: 2022-04-06 17:52:06.934781

"""

# revision identifiers, used by Alembic.
revision = "a9987414cf36"
down_revision = "e2d406ada25c"

from alembic import op
import sqlalchemy as sa


def upgrade():
    # potential improvements for faster search
    op.drop_index("certificate_associations_ix", table_name="certificate_associations")
    op.create_index(
        "certificate_associations_ix",
        "certificate_associations",
        ["domain_id", "certificate_id"],
        unique=True,
    )

    op.drop_index(
        "certificate_destination_associations_ix",
        table_name="certificate_destination_associations",
    )
    op.create_index(
        "certificate_destination_associations_ix",
        "certificate_destination_associations",
        ["destination_id", "certificate_id"],
        unique=True,
    )

    op.drop_index(
        "certificate_source_associations_ix",
        table_name="certificate_source_associations",
    )
    op.create_index(
        "certificate_source_associations_ix",
        "certificate_source_associations",
        ["source_id", "certificate_id"],
        unique=True,
    )

    op.drop_constraint("certificates_name_key", "certificates", type_="unique")
    op.drop_constraint("certificates_name_key1", "certificates", type_="unique")

    op.drop_index("ix_domains_name_gin", table_name="domains")

    op.drop_index("ix_certificates_name", table_name="certificates")
    op.create_index(op.f("ix_certificates_name"), "certificates", ["name"], unique=True)

    op.drop_index("roles_authorities_ix", table_name="roles_authorities")
    op.create_index(
        "roles_authorities_ix",
        "roles_authorities",
        ["authority_id", "role_id"],
        unique=True,
    )

    op.drop_index("roles_certificates_ix", table_name="roles_certificates")
    op.create_index(
        "roles_certificates_ix",
        "roles_certificates",
        ["certificate_id", "role_id"],
        unique=True,
    )
    # ### end Alembic commands ###


def downgrade():
    op.drop_index("roles_certificates_ix", table_name="roles_certificates")
    op.create_index(
        "roles_certificates_ix",
        "roles_certificates",
        ["certificate_id", "role_id"],
        unique=False,
    )
    op.drop_index("roles_authorities_ix", table_name="roles_authorities")
    op.create_index(
        "roles_authorities_ix",
        "roles_authorities",
        ["authority_id", "role_id"],
        unique=False,
    )
    op.create_index("ix_domains_name_gin", "domains", ["name"], unique=False)
    op.drop_index(op.f("ix_certificates_name"), table_name="certificates")
    op.create_index("ix_certificates_name", "certificates", ["name"], unique=False)
    op.create_unique_constraint("certificates_name_key1", "certificates", ["name"])
    op.create_unique_constraint("certificates_name_key", "certificates", ["name"])
    op.drop_index(
        "certificate_source_associations_ix",
        table_name="certificate_source_associations",
    )
    op.create_index(
        "certificate_source_associations_ix",
        "certificate_source_associations",
        ["source_id", "certificate_id"],
        unique=False,
    )
    op.drop_index(
        "certificate_destination_associations_ix",
        table_name="certificate_destination_associations",
    )
    op.create_index(
        "certificate_destination_associations_ix",
        "certificate_destination_associations",
        ["destination_id", "certificate_id"],
        unique=False,
    )
    op.drop_index("certificate_associations_ix", table_name="certificate_associations")
    op.create_index(
        "certificate_associations_ix",
        "certificate_associations",
        ["domain_id", "certificate_id"],
        unique=False,
    )
    # ### end Alembic commands ###
