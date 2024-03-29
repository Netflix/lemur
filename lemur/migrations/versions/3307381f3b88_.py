"""
Refactor authority columns and associates an authorities root certificate with a certificate stored in the
certificate tables.

Migrates existing authority owners to associated roles.
Migrates existing certificate owners to associated role.

Revision ID: 3307381f3b88
Revises: 412b22cb656a
Create Date: 2016-05-20 17:33:04.360687

"""

# revision identifiers, used by Alembic.
revision = "3307381f3b88"
down_revision = "412b22cb656a"

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text
from sqlalchemy.dialects import postgresql


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.alter_column(
        "authorities", "owner", existing_type=sa.VARCHAR(length=128), nullable=True
    )
    op.drop_column("authorities", "not_after")
    op.drop_column("authorities", "bits")
    op.drop_column("authorities", "cn")
    op.drop_column("authorities", "not_before")
    op.add_column(
        "certificates", sa.Column("root_authority_id", sa.Integer(), nullable=True)
    )
    op.alter_column("certificates", "body", existing_type=sa.TEXT(), nullable=False)
    op.alter_column(
        "certificates", "owner", existing_type=sa.VARCHAR(length=128), nullable=True
    )
    op.drop_constraint(
        "certificates_authority_id_fkey", "certificates", type_="foreignkey"
    )
    op.create_foreign_key(
        None,
        "certificates",
        "authorities",
        ["authority_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        None,
        "certificates",
        "authorities",
        ["root_authority_id"],
        ["id"],
        ondelete="CASCADE",
    )
    ### end Alembic commands ###

    # link existing certificate to their authority certificates
    conn = op.get_bind()
    for id, body, owner in conn.execute(
        text("select id, body, owner from authorities")
    ):
        if not owner:
            owner = "lemur@nobody"

        # look up certificate by body, if duplications are found, pick one
        stmt = text("select id from certificates where body=:body")
        stmt = stmt.bindparams(body=body)
        root_certificate = conn.execute(stmt).fetchone()
        if root_certificate:
            stmt = text(
                "update certificates set root_authority_id=:root_authority_id where id=:id"
            )
            stmt = stmt.bindparams(root_authority_id=id, id=root_certificate[0])
            op.execute(stmt)

        # link owner roles to their authorities
        stmt = text("select id from roles where name=:name")
        stmt = stmt.bindparams(name=owner)
        owner_role = conn.execute(stmt).fetchone()

        if not owner_role:
            stmt = text(
                "insert into roles (name, description) values (:name, :description)"
            )
            stmt = stmt.bindparams(
                name=owner, description="Lemur generated role or existing owner."
            )
            op.execute(stmt)

        stmt = text("select id from roles where name=:name")
        stmt = stmt.bindparams(name=owner)
        owner_role = conn.execute(stmt).fetchone()

        stmt = text(
            "select * from roles_authorities where role_id=:role_id and authority_id=:authority_id"
        )
        stmt = stmt.bindparams(role_id=owner_role[0], authority_id=id)
        exists = conn.execute(stmt).fetchone()

        if not exists:
            stmt = text(
                "insert into roles_authorities (role_id, authority_id) values (:role_id, :authority_id)"
            )
            stmt = stmt.bindparams(role_id=owner_role[0], authority_id=id)
            op.execute(stmt)

    # link owner roles to their certificates
    for id, owner in conn.execute(text("select id, owner from certificates")):
        if not owner:
            owner = "lemur@nobody"

        stmt = text("select id from roles where name=:name")
        stmt = stmt.bindparams(name=owner)
        owner_role = conn.execute(stmt).fetchone()

        if not owner_role:
            stmt = text(
                "insert into roles (name, description) values (:name, :description)"
            )
            stmt = stmt.bindparams(
                name=owner, description="Lemur generated role or existing owner."
            )
            op.execute(stmt)

        # link owner roles to their authorities
        stmt = text("select id from roles where name=:name")
        stmt = stmt.bindparams(name=owner)
        owner_role = conn.execute(stmt).fetchone()

        stmt = text(
            "select * from roles_certificates where role_id=:role_id and certificate_id=:certificate_id"
        )
        stmt = stmt.bindparams(role_id=owner_role[0], certificate_id=id)
        exists = conn.execute(stmt).fetchone()

        if not exists:
            stmt = text(
                "insert into roles_certificates (role_id, certificate_id) values (:role_id, :certificate_id)"
            )
            stmt = stmt.bindparams(role_id=owner_role[0], certificate_id=id)
            op.execute(stmt)


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, "certificates", type_="foreignkey")
    op.drop_constraint(None, "certificates", type_="foreignkey")
    op.create_foreign_key(
        "certificates_authority_id_fkey",
        "certificates",
        "authorities",
        ["authority_id"],
        ["id"],
    )
    op.alter_column(
        "certificates", "owner", existing_type=sa.VARCHAR(length=128), nullable=True
    )
    op.alter_column("certificates", "body", existing_type=sa.TEXT(), nullable=True)
    op.drop_column("certificates", "root_authority_id")
    op.add_column(
        "authorities",
        sa.Column(
            "not_before", postgresql.TIMESTAMP(), autoincrement=False, nullable=True
        ),
    )
    op.add_column(
        "authorities",
        sa.Column("cn", sa.VARCHAR(length=128), autoincrement=False, nullable=True),
    )
    op.add_column(
        "authorities",
        sa.Column("bits", sa.INTEGER(), autoincrement=False, nullable=True),
    )
    op.add_column(
        "authorities",
        sa.Column(
            "not_after", postgresql.TIMESTAMP(), autoincrement=False, nullable=True
        ),
    )
    op.alter_column(
        "authorities", "owner", existing_type=sa.VARCHAR(length=128), nullable=True
    )
    ### end Alembic commands ###
