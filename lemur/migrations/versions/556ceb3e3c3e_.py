"""Add Pending Certificates models and relations

Revision ID: 556ceb3e3c3e
Revises: 47baffaae1a7
Create Date: 2018-01-05 01:18:45.571595

"""

# revision identifiers, used by Alembic.
revision = '556ceb3e3c3e'
down_revision = '47baffaae1a7'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('pending_certs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('external_id', sa.String(length=128), nullable=True),
    sa.Column('owner', sa.String(length=128), nullable=False),
    sa.Column('name', sa.String(length=256), nullable=True),
    sa.Column('description', sa.String(length=1024), nullable=True),
    sa.Column('notify', sa.Boolean(), nullable=True),
    sa.Column('number_attempts', sa.Integer(), nullable=True),
    sa.Column('rename', sa.Boolean(), nullable=True),
    sa.Column('cn', sa.String(length=128), nullable=True),
    sa.Column('csr', sa.Text(), nullable=False),
    sa.Column('chain', sa.Text(), nullable=True),
    sa.Column('private_key', lemur.utils.Vault(), nullable=True),
    sa.Column('date_created', sqlalchemy_utils.types.arrow.ArrowType(), server_default=sa.text('now()'), nullable=False),
    sa.Column('status', sa.String(length=128), nullable=True),
    sa.Column('rotation', sa.Boolean(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('authority_id', sa.Integer(), nullable=True),
    sa.Column('root_authority_id', sa.Integer(), nullable=True),
    sa.Column('rotation_policy_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['authority_id'], ['authorities.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['root_authority_id'], ['authorities.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['rotation_policy_id'], ['rotation_policies.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('pending_cert_destination_associations',
    sa.Column('destination_id', sa.Integer(), nullable=True),
    sa.Column('pending_cert_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['destination_id'], ['destinations.id'], ondelete='cascade'),
    sa.ForeignKeyConstraint(['pending_cert_id'], ['pending_certs.id'], ondelete='cascade')
    )
    op.create_index('pending_cert_destination_associations_ix', 'pending_cert_destination_associations', ['destination_id', 'pending_cert_id'], unique=False)
    op.create_table('pending_cert_notification_associations',
    sa.Column('notification_id', sa.Integer(), nullable=True),
    sa.Column('pending_cert_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['notification_id'], ['notifications.id'], ondelete='cascade'),
    sa.ForeignKeyConstraint(['pending_cert_id'], ['pending_certs.id'], ondelete='cascade')
    )
    op.create_index('pending_cert_notification_associations_ix', 'pending_cert_notification_associations', ['notification_id', 'pending_cert_id'], unique=False)
    op.create_table('pending_cert_replacement_associations',
    sa.Column('replaced_certificate_id', sa.Integer(), nullable=True),
    sa.Column('pending_cert_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['pending_cert_id'], ['pending_certs.id'], ondelete='cascade'),
    sa.ForeignKeyConstraint(['replaced_certificate_id'], ['certificates.id'], ondelete='cascade')
    )
    op.create_index('pending_cert_replacement_associations_ix', 'pending_cert_replacement_associations', ['replaced_certificate_id', 'pending_cert_id'], unique=False)
    op.create_table('pending_cert_role_associations',
    sa.Column('pending_cert_id', sa.Integer(), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['pending_cert_id'], ['pending_certs.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], )
    )
    op.create_index('pending_cert_role_associations_ix', 'pending_cert_role_associations', ['pending_cert_id', 'role_id'], unique=False)
    op.create_table('pending_cert_source_associations',
    sa.Column('source_id', sa.Integer(), nullable=True),
    sa.Column('pending_cert_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['pending_cert_id'], ['pending_certs.id'], ondelete='cascade'),
    sa.ForeignKeyConstraint(['source_id'], ['sources.id'], ondelete='cascade')
    )
    op.create_index('pending_cert_source_associations_ix', 'pending_cert_source_associations', ['source_id', 'pending_cert_id'], unique=False)
    op.create_table('roles_authorities',
    sa.Column('authority_id', sa.Integer(), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['authority_id'], ['authorities.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], )
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('pending_cert_source_associations_ix', table_name='pending_cert_source_associations')
    op.drop_table('pending_cert_source_associations')
    op.drop_index('pending_cert_role_associations_ix', table_name='pending_cert_role_associations')
    op.drop_table('pending_cert_role_associations')
    op.drop_index('pending_cert_replacement_associations_ix', table_name='pending_cert_replacement_associations')
    op.drop_table('pending_cert_replacement_associations')
    op.drop_index('pending_cert_notification_associations_ix', table_name='pending_cert_notification_associations')
    op.drop_table('pending_cert_notification_associations')
    op.drop_index('pending_cert_destination_associations_ix', table_name='pending_cert_destination_associations')
    op.drop_table('pending_cert_destination_associations')
    op.drop_table('pending_certs')
    # ### end Alembic commands ###
