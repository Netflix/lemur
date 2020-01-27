"""Create tables and columns for the acme issuer.

Revision ID: 3adfdd6598df
Revises: 556ceb3e3c3e
Create Date: 2018-04-10 13:25:47.007556

"""

# revision identifiers, used by Alembic.
revision = "3adfdd6598df"
down_revision = "556ceb3e3c3e"

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy_utils import ArrowType

from lemur.utils import Vault


def upgrade():
    # create provider table
    print("Creating dns_providers table")
    op.create_table(
        "dns_providers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=True),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("provider_type", sa.String(length=256), nullable=True),
        sa.Column("credentials", Vault(), nullable=True),
        sa.Column("api_endpoint", sa.String(length=256), nullable=True),
        sa.Column(
            "date_created", ArrowType(), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("status", sa.String(length=128), nullable=True),
        sa.Column("options", JSON),
        sa.Column("domains", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    print("Adding dns_provider_id column to certificates")
    op.add_column(
        "certificates", sa.Column("dns_provider_id", sa.Integer(), nullable=True)
    )
    print("Adding dns_provider_id column to pending_certs")
    op.add_column(
        "pending_certs", sa.Column("dns_provider_id", sa.Integer(), nullable=True)
    )
    print("Adding options column to pending_certs")
    op.add_column("pending_certs", sa.Column("options", JSON))

    print("Creating pending_dns_authorizations table")
    op.create_table(
        "pending_dns_authorizations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("account_number", sa.String(length=128), nullable=True),
        sa.Column("domains", JSON, nullable=True),
        sa.Column("dns_provider_type", sa.String(length=128), nullable=True),
        sa.Column("options", JSON, nullable=True),
    )

    print("Creating certificates_dns_providers_fk foreign key")
    op.create_foreign_key(
        "certificates_dns_providers_fk",
        "certificates",
        "dns_providers",
        ["dns_provider_id"],
        ["id"],
        ondelete="cascade",
    )

    print("Altering column types in the api_keys table")
    op.alter_column("api_keys", "issued_at", existing_type=sa.BIGINT(), nullable=True)
    op.alter_column("api_keys", "revoked", existing_type=sa.BOOLEAN(), nullable=True)
    op.alter_column("api_keys", "ttl", existing_type=sa.BIGINT(), nullable=True)
    op.alter_column("api_keys", "user_id", existing_type=sa.INTEGER(), nullable=True)

    print("Creating dns_providers_id foreign key on pending_certs table")
    op.create_foreign_key(
        None,
        "pending_certs",
        "dns_providers",
        ["dns_provider_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade():
    print("Removing dns_providers_id foreign key on pending_certs table")
    op.drop_constraint(None, "pending_certs", type_="foreignkey")
    print("Reverting column types in the api_keys table")
    op.alter_column("api_keys", "user_id", existing_type=sa.INTEGER(), nullable=False)
    op.alter_column("api_keys", "ttl", existing_type=sa.BIGINT(), nullable=False)
    op.alter_column("api_keys", "revoked", existing_type=sa.BOOLEAN(), nullable=False)
    op.alter_column("api_keys", "issued_at", existing_type=sa.BIGINT(), nullable=False)
    print("Reverting certificates_dns_providers_fk foreign key")
    op.drop_constraint(
        "certificates_dns_providers_fk", "certificates", type_="foreignkey"
    )

    print("Dropping pending_dns_authorizations table")
    op.drop_table("pending_dns_authorizations")
    print("Undoing modifications to pending_certs table")
    op.drop_column("pending_certs", "options")
    op.drop_column("pending_certs", "dns_provider_id")
    print("Undoing modifications to certificates table")
    op.drop_column("certificates", "dns_provider_id")

    print("Deleting dns_providers table")
    op.drop_table("dns_providers")
