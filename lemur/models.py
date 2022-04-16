"""
.. module: lemur.models
    :platform: Unix
    :synopsis: This module contains all of the associative tables
    that help define the many to many relationships established in Lemur

    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy import Column, Integer, ForeignKey, Index, UniqueConstraint

from lemur.database import db

certificate_destination_associations = db.Table(
    "certificate_destination_associations",
    Column(
        "destination_id", Integer, ForeignKey("destinations.id", ondelete="cascade")
    ),
    Column(
        "certificate_id", Integer, ForeignKey("certificates.id", ondelete="cascade")
    ),
)

Index(
    "certificate_destination_associations_ix",
    certificate_destination_associations.c.destination_id,
    certificate_destination_associations.c.certificate_id,
    unique=True
)

certificate_source_associations = db.Table(
    "certificate_source_associations",
    Column("source_id", Integer, ForeignKey("sources.id", ondelete="cascade")),
    Column(
        "certificate_id", Integer, ForeignKey("certificates.id", ondelete="cascade")
    ),
)

Index(
    "certificate_source_associations_ix",
    certificate_source_associations.c.source_id,
    certificate_source_associations.c.certificate_id,
    unique=True
)

certificate_notification_associations = db.Table(
    "certificate_notification_associations",
    Column(
        "notification_id", Integer, ForeignKey("notifications.id", ondelete="cascade")
    ),
    Column(
        "certificate_id", Integer, ForeignKey("certificates.id", ondelete="cascade")
    ),
    Column("id", Integer, primary_key=True, autoincrement=True),
    UniqueConstraint("notification_id", "certificate_id", name="uq_dest_not_ids"),
)

Index(
    "certificate_notification_associations_ix",
    certificate_notification_associations.c.notification_id,
    certificate_notification_associations.c.certificate_id,
)

certificate_replacement_associations = db.Table(
    "certificate_replacement_associations",
    Column(
        "replaced_certificate_id",
        Integer,
        ForeignKey("certificates.id", ondelete="cascade"),
    ),
    Column(
        "certificate_id", Integer, ForeignKey("certificates.id", ondelete="cascade")
    ),
)

Index(
    "certificate_replacement_associations_ix",
    certificate_replacement_associations.c.replaced_certificate_id,
    certificate_replacement_associations.c.certificate_id,
    unique=True,
)

roles_authorities = db.Table(
    "roles_authorities",
    Column("authority_id", Integer, ForeignKey("authorities.id")),
    Column("role_id", Integer, ForeignKey("roles.id")),
)

Index(
    "roles_authorities_ix",
    roles_authorities.c.authority_id,
    roles_authorities.c.role_id,
    unique=True
)

roles_certificates = db.Table(
    "roles_certificates",
    Column("certificate_id", Integer, ForeignKey("certificates.id")),
    Column("role_id", Integer, ForeignKey("roles.id")),
)

Index(
    "roles_certificates_ix",
    roles_certificates.c.certificate_id,
    roles_certificates.c.role_id,
    unique=True
)


roles_users = db.Table(
    "roles_users",
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("role_id", Integer, ForeignKey("roles.id")),
)

Index("roles_users_ix", roles_users.c.user_id, roles_users.c.role_id)


policies_ciphers = db.Table(
    "policies_ciphers",
    Column("cipher_id", Integer, ForeignKey("ciphers.id")),
    Column("policy_id", Integer, ForeignKey("policy.id")),
)

Index("policies_ciphers_ix", policies_ciphers.c.cipher_id, policies_ciphers.c.policy_id)


pending_cert_destination_associations = db.Table(
    "pending_cert_destination_associations",
    Column(
        "destination_id", Integer, ForeignKey("destinations.id", ondelete="cascade")
    ),
    Column(
        "pending_cert_id", Integer, ForeignKey("pending_certs.id", ondelete="cascade")
    ),
)

Index(
    "pending_cert_destination_associations_ix",
    pending_cert_destination_associations.c.destination_id,
    pending_cert_destination_associations.c.pending_cert_id,
)


pending_cert_notification_associations = db.Table(
    "pending_cert_notification_associations",
    Column(
        "notification_id", Integer, ForeignKey("notifications.id", ondelete="cascade")
    ),
    Column(
        "pending_cert_id", Integer, ForeignKey("pending_certs.id", ondelete="cascade")
    ),
)

Index(
    "pending_cert_notification_associations_ix",
    pending_cert_notification_associations.c.notification_id,
    pending_cert_notification_associations.c.pending_cert_id,
)

pending_cert_source_associations = db.Table(
    "pending_cert_source_associations",
    Column("source_id", Integer, ForeignKey("sources.id", ondelete="cascade")),
    Column(
        "pending_cert_id", Integer, ForeignKey("pending_certs.id", ondelete="cascade")
    ),
)

Index(
    "pending_cert_source_associations_ix",
    pending_cert_source_associations.c.source_id,
    pending_cert_source_associations.c.pending_cert_id,
)

pending_cert_replacement_associations = db.Table(
    "pending_cert_replacement_associations",
    Column(
        "replaced_certificate_id",
        Integer,
        ForeignKey("certificates.id", ondelete="cascade"),
    ),
    Column(
        "pending_cert_id", Integer, ForeignKey("pending_certs.id", ondelete="cascade")
    ),
)

Index(
    "pending_cert_replacement_associations_ix",
    pending_cert_replacement_associations.c.replaced_certificate_id,
    pending_cert_replacement_associations.c.pending_cert_id,
)

pending_cert_role_associations = db.Table(
    "pending_cert_role_associations",
    Column("pending_cert_id", Integer, ForeignKey("pending_certs.id")),
    Column("role_id", Integer, ForeignKey("roles.id")),
)

Index(
    "pending_cert_role_associations_ix",
    pending_cert_role_associations.c.pending_cert_id,
    pending_cert_role_associations.c.role_id,
)
