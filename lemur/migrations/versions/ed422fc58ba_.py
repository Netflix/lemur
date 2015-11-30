"""Migrates the private key encrypted column from AES to fernet encryption scheme.

Revision ID: ed422fc58ba
Revises: 4bcfa2c36623
Create Date: 2015-10-23 09:19:28.654126

"""
import base64

# revision identifiers, used by Alembic.
revision = 'ed422fc58ba'
down_revision = '4bcfa2c36623'
import six

from StringIO import StringIO

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet, MultiFernet

from flask import current_app
from lemur.common.utils import get_psuedo_random_string

conn = op.get_bind()

op.drop_table('encrypted_keys')
op.drop_table('encrypted_passwords')

# helper tables to migrate data
temp_key_table = op.create_table('encrypted_keys',
                                 sa.Column('id', sa.Integer(), nullable=False),
                                 sa.Column('aes', sa.Binary()),
                                 sa.Column('fernet', sa.Binary()),
                                 sa.PrimaryKeyConstraint('id')
                                 )

# helper table to migrate data
temp_password_table = op.create_table('encrypted_passwords',
                                      sa.Column('id', sa.Integer(), nullable=False),
                                      sa.Column('aes', sa.Binary()),
                                      sa.Column('fernet', sa.Binary()),
                                      sa.PrimaryKeyConstraint('id')
                                      )


# From http://sqlalchemy-utils.readthedocs.org/en/latest/_modules/sqlalchemy_utils/types/encrypted.html#EncryptedType
# for migration purposes only
class EncryptionDecryptionBaseEngine(object):
    """A base encryption and decryption engine.

    This class must be sub-classed in order to create
    new engines.
    """

    def _update_key(self, key):
        if isinstance(key, six.string_types):
            key = key.encode()
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key)
        engine_key = digest.finalize()

        self._initialize_engine(engine_key)

    def encrypt(self, value):
        raise NotImplementedError('Subclasses must implement this!')

    def decrypt(self, value):
        raise NotImplementedError('Subclasses must implement this!')


class AesEngine(EncryptionDecryptionBaseEngine):
    """Provide AES encryption and decryption methods."""

    BLOCK_SIZE = 16
    PADDING = six.b('*')

    def _initialize_engine(self, parent_class_key):
        self.secret_key = parent_class_key
        self.iv = self.secret_key[:16]
        self.cipher = Cipher(
            algorithms.AES(self.secret_key),
            modes.CBC(self.iv),
            backend=default_backend()
        )

    def _pad(self, value):
        """Pad the message to be encrypted, if needed."""
        BS = self.BLOCK_SIZE
        P = self.PADDING
        padded = (value + (BS - len(value) % BS) * P)
        return padded

    def encrypt(self, value):
        if not isinstance(value, six.string_types):
            value = repr(value)
        if isinstance(value, six.text_type):
            value = str(value)
        value = value.encode()
        value = self._pad(value)
        encryptor = self.cipher.encryptor()
        encrypted = encryptor.update(value) + encryptor.finalize()
        encrypted = base64.b64encode(encrypted)
        return encrypted

    def decrypt(self, value):
        if isinstance(value, six.text_type):
            value = str(value)
        decryptor = self.cipher.decryptor()
        decrypted = base64.b64decode(value)
        decrypted = decryptor.update(decrypted) + decryptor.finalize()
        decrypted = decrypted.rstrip(self.PADDING)
        if not isinstance(decrypted, six.string_types):
            decrypted = decrypted.decode('utf-8')
        return decrypted


def migrate_to_fernet(aes_encrypted, old_key, new_key):
    """
    Will attempt to migrate an aes encrypted to fernet encryption
    :param aes_encrypted:
    :return: fernet encrypted value
    """
    engine = AesEngine()
    engine._update_key(old_key)

    if not isinstance(aes_encrypted, six.string_types):
        return

    aes_decrypted = engine.decrypt(aes_encrypted)
    fernet_encrypted = MultiFernet([Fernet(k) for k in new_key]).encrypt(bytes(aes_decrypted))

    # sanity check
    fernet_decrypted = MultiFernet([Fernet(k) for k in new_key]).decrypt(fernet_encrypted)
    if fernet_decrypted != aes_decrypted:
        raise Exception("WARNING: Decrypted values do not match!")

    return fernet_encrypted


def migrate_from_fernet(fernet_encrypted, old_key, new_key):
    """
    Will attempt to migrate from a fernet encryption to aes
    :param fernet_encrypted:
    :return:
    """
    engine = AesEngine()
    engine._update_key(new_key)

    fernet_decrypted = MultiFernet([Fernet(k) for k in old_key]).decrypt(fernet_encrypted)
    aes_encrypted = engine.encrypt(fernet_decrypted)

    # sanity check
    aes_decrypted = engine.decrypt(aes_encrypted)
    if fernet_decrypted != aes_decrypted:
        raise Exception("WARNING: Decrypted values do not match!")

    return aes_encrypted


def upgrade():
    old_key = current_app.config.get('LEMUR_ENCRYPTION_KEY')
    print "Using: {0} as decryption key".format(old_key)
    # generate a new fernet token

    if current_app.config.get('LEMUR_ENCRYPTION_KEYS'):
        new_key = current_app.config.get('LEMUR_ENCRYPTION_KEYS')
    else:
        new_key = [Fernet.generate_key()]

    print "Using: {0} as new encryption key, save this and place it in your configuration!".format(new_key)

    # migrate private_keys
    temp_keys = []
    for id, private_key in conn.execute(text('select id, private_key from certificates where private_key is not null')):
        aes_encrypted = StringIO(private_key).read()
        fernet_encrypted = migrate_to_fernet(aes_encrypted, old_key, new_key)
        temp_keys.append({'id': id, 'aes': aes_encrypted, 'fernet': fernet_encrypted})

    op.bulk_insert(temp_key_table, temp_keys)

    for id, fernet in conn.execute(text('select id, fernet from encrypted_keys')):
        stmt = text("update certificates set private_key=:key where id=:id")
        stmt = stmt.bindparams(key=fernet, id=id)
        op.execute(stmt)
        print "Certificate {0} has been migrated".format(id)

    # migrate role_passwords
    temp_passwords = []
    for id, password in conn.execute(text('select id, password from roles where password is not null')):
        aes_encrypted = StringIO(password).read()
        fernet_encrypted = migrate_to_fernet(aes_encrypted, old_key, new_key)
        temp_passwords.append({'id': id, 'aes': aes_encrypted, 'fernet': fernet_encrypted})

    op.bulk_insert(temp_password_table, temp_passwords)

    for id, fernet in conn.execute(text('select id, fernet from encrypted_passwords')):
        stmt = text("update roles set password=:password where id=:id")
        stmt = stmt.bindparams(password=fernet, id=id)
        print stmt
        op.execute(stmt)
        print "Password {0} has been migrated".format(id)

    op.drop_table('encrypted_keys')
    op.drop_table('encrypted_passwords')


def downgrade():
    old_key = current_app.config.get('LEMUR_ENCRYPTION_KEYS')
    print "Using: {0} as decryption key(s)".format(old_key)

    # generate aes valid key
    if current_app.config.get('LEMUR_ENCRYPTION_KEY'):
        new_key = current_app.config.get('LEMUR_ENCRYPTION_KEY')
    else:
        new_key = get_psuedo_random_string()
    print "Using: {0} as the encryption key, save this and place it in your configuration!".format(new_key)

    # migrate keys
    temp_keys = []
    for id, private_key in conn.execute(text('select id, private_key from certificates where private_key is not null')):
        fernet_encrypted = StringIO(private_key).read()
        aes_encrypted = migrate_from_fernet(fernet_encrypted, old_key, new_key)
        temp_keys.append({'id': id, 'aes': aes_encrypted, 'fernet': fernet_encrypted})

    op.bulk_insert(temp_key_table, temp_keys)

    for id, aes in conn.execute(text('select id, aes from encrypted_keys')):
        stmt = text("update certificates set private_key=:key where id=:id")
        stmt = stmt.bindparams(key=aes, id=id)
        print stmt
        op.execute(stmt)
        print "Certificate {0} has been migrated".format(id)

    # migrate role_passwords
    temp_passwords = []
    for id, password in conn.execute(text('select id, password from roles where password is not null')):
        fernet_encrypted = StringIO(password).read()
        aes_encrypted = migrate_from_fernet(fernet_encrypted, old_key, new_key)
        temp_passwords.append({'id': id, 'aes': aes_encrypted, 'fernet': fernet_encrypted})

    op.bulk_insert(temp_password_table, temp_passwords)

    for id, aes in conn.execute(text('select id, aes from encrypted_passwords')):
        stmt = text("update roles set password=:password where id=:id")
        stmt = stmt.bindparams(password=aes, id=id)
        op.execute(stmt)
        print "Password {0} has been migrated".format(id)

    op.drop_table('encrypted_keys')
    op.drop_table('encrypted_passwords')
