"""
.. module: lemur.certificate.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import re
import time
from collections import defaultdict
from itertools import groupby

import arrow
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from flask import current_app
from sentry_sdk import capture_exception
from sqlalchemy import and_, func, or_, not_, cast, Integer
from sqlalchemy.sql.expression import false, true

from lemur import database
from lemur.authorities.models import Authority
from lemur.certificates.models import Certificate, CertificateAssociation
from lemur.certificates.schemas import CertificateOutputSchema, CertificateInputSchema
from lemur.common.utils import generate_private_key, truthiness, parse_serial, get_certificate_via_tls, windowed_query
from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS
from lemur.destinations.models import Destination
from lemur.domains.models import Domain
from lemur.domains.service import is_authorized_for_domain
from lemur.endpoints import service as endpoint_service
from lemur.extensions import metrics, signals
from lemur.notifications.messaging import send_revocation_notification
from lemur.notifications.models import Notification
from lemur.pending_certificates.models import PendingCertificate
from lemur.plugins.base import plugins
from lemur.plugins.utils import get_plugin_option
from lemur.roles import service as role_service
from lemur.roles.models import Role

csr_created = signals.signal("csr_created", "CSR generated")
csr_imported = signals.signal("csr_imported", "CSR imported from external source")
certificate_issued = signals.signal(
    "certificate_issued", "Authority issued a certificate"
)
certificate_imported = signals.signal(
    "certificate_imported", "Certificate imported from external source"
)


def get(cert_id):
    """
    Retrieves certificate by its ID.

    :param cert_id:
    :return:
    """
    return database.get(Certificate, cert_id)


def get_by_name(name):
    """
    Retrieves certificate by its Name.

    :param name:
    :return:
    """
    return database.get(Certificate, name, field="name")


def get_by_serial(serial):
    """
    Retrieves certificate(s) by serial number.
    :param serial:
    :return:
    """
    if isinstance(serial, int):
        # although serial is a number, the DB column is String(128)
        serial = str(serial)
    return Certificate.query.filter(Certificate.serial == serial).all()


def get_by_attributes(conditions):
    """
    Retrieves certificate(s) by conditions given in a hash of given key=>value pairs.
    :param serial:
    :return:
    """
    # Ensure that each of the given conditions corresponds to actual columns
    # if not, silently remove it
    for attr in conditions.keys():
        if attr not in Certificate.__table__.columns:
            conditions.pop(attr)

    query = database.session_query(Certificate)
    return database.find_all(query, Certificate, conditions).all()


def delete(cert_id):
    """
    Delete's a certificate.

    :param cert_id:
    """
    database.delete(get(cert_id))


def get_all_certs():
    """
    Retrieves all certificates within Lemur.

    :return:
    """
    return Certificate.query.all()


def get_all_valid_certs(authority_plugin_name, paginate=False, page=1, count=1000, created_on_or_before=None):
    """
    Retrieves all valid (not expired & not revoked) certificates within Lemur, for the given authority plugin names
    ignored if no authority_plugin_name provided.

    Note that depending on the DB size retrieving all certificates might an expensive operation
    :param paginate: option to use pagination, for large number of certificates. default to false
    :param page: the page to turn. default to 1
    :param count: number of return certificates per page. default 1000
    :param created_on_or_before: optional Arrow date to select only certificates issued on or before the date

    :return: list of certificates to check for revocation
    """
    assert (page > 0)
    query = database.session_query(Certificate) if paginate else Certificate.query

    if authority_plugin_name:
        query = query.outerjoin(Authority, Authority.id == Certificate.authority_id)\
            .filter(Certificate.not_after > arrow.now().format("YYYY-MM-DD"))\
            .filter(Authority.plugin_name.in_(authority_plugin_name))\
            .filter(Certificate.revoked.is_(False))

    else:
        query = query.filter(Certificate.not_after > arrow.now().format("YYYY-MM-DD"))\
            .filter(Certificate.revoked.is_(False))

    if created_on_or_before:
        query = query.filter(Certificate.date_created <= created_on_or_before.format("YYYY-MM-DD"))

    if paginate:
        args = {"page": page, "count": count, "sort_by": "id", "sort_dir": "desc"}
        items = database.sort_and_page(query, Certificate, args)
        return items['items']

    return query.all()


def get_all_pending_cleaning_expired(source):
    """
    Retrieves all certificates that are available for cleaning. These are certificates which are expired and are not
    attached to any endpoints.

    :param source: the source to search for certificates
    :return: list of pending certificates
    """
    return (
        Certificate.query.filter(Certificate.sources.any(id=source.id))
        .filter(not_(Certificate.endpoints.any()))
        .filter(Certificate.expired)
        .all()
    )


def get_all_certs_attached_to_endpoint_without_autorotate():
    """
    Retrieves all certificates that are attached to an endpoint, but that do not have autorotate enabled.

    :return: list of certificates attached to an endpoint without autorotate
    """
    return (
        Certificate.query.filter(Certificate.endpoints.any())
        .filter(Certificate.rotation == false())
        .filter(Certificate.revoked == false())
        .filter(Certificate.not_after >= arrow.now())
        .filter(not_(Certificate.replaced.any()))
        .all()  # noqa
    )


def get_all_certs_attached_to_destination_without_autorotate(plugin_name=None):
    """
    Retrieves all certificates that are attached to a destination, but that do not have autorotate enabled.

    :param plugin_name: Optional destination plugin name to query. Queries certificates attached to any destination if not provided.
    :return: list of certificates attached to a destination without autorotate
    """
    if plugin_name:
        return (
            Certificate.query.filter(Certificate.destinations.any(plugin_name=plugin_name))
            .filter(Certificate.rotation == false())
            .filter(Certificate.revoked == false())
            .filter(Certificate.not_after >= arrow.now())
            .filter(not_(Certificate.replaced.any()))
            .all()  # noqa
        )

    return (
        Certificate.query.filter(Certificate.destinations.any())
        .filter(Certificate.rotation == false())
        .filter(Certificate.revoked == false())
        .filter(Certificate.not_after >= arrow.now())
        .filter(not_(Certificate.replaced.any()))
        .all()  # noqa
    )


def get_all_pending_cleaning_expiring_in_days(source, days_to_expire):
    """
    Retrieves all certificates that are available for cleaning, not attached to endpoint,
    and within X days from expiration.

    :param days_to_expire: defines how many days till the certificate is expired
    :param source: the source to search for certificates
    :return: list of pending certificates
    """
    expiration_window = arrow.now().shift(days=+days_to_expire).format("YYYY-MM-DD")
    return (
        Certificate.query.filter(Certificate.sources.any(id=source.id))
        .filter(not_(Certificate.endpoints.any()))
        .filter(Certificate.not_after < expiration_window)
        .all()
    )


def get_all_pending_cleaning_issued_since_days(source, days_since_issuance):
    """
    Retrieves all certificates that are available for cleaning: not attached to endpoint, and X days since issuance.

    :param days_since_issuance: defines how many days since the certificate is issued
    :param source: the source to search for certificates
    :return: list of pending certificates
    """
    not_in_use_window = (
        arrow.now().shift(days=-days_since_issuance).format("YYYY-MM-DD")
    )
    return (
        Certificate.query.filter(Certificate.sources.any(id=source.id))
        .filter(not_(Certificate.endpoints.any()))
        .filter(Certificate.date_created > not_in_use_window)
        .all()
    )


def get_all_pending_reissue():
    """
    Retrieves all certificates that need to be rotated.

    Must be X days from expiration, uses the certificates rotation
    policy to determine how many days from expiration the certificate must be
    for rotation to be pending.

    :return:
    """
    return (
        Certificate.query.filter(Certificate.rotation == true())
        .filter(not_(Certificate.replaced.any()))
        .filter(Certificate.in_rotation_window == true())
        .all()
    )  # noqa


def find_duplicates(cert):
    """
    Finds certificates that already exist within Lemur. We do this by looking for
    certificate bodies that are the same. This is the most reliable way to determine
    if a certificate is already being tracked by Lemur.

    :param cert:
    :return:
    """
    if cert["chain"]:
        return Certificate.query.filter_by(
            body=cert["body"].strip(), chain=cert["chain"].strip()
        ).all()
    else:
        return Certificate.query.filter_by(body=cert["body"].strip(), chain=None).all()


def list_recent_valid_certs_issued_by_authority(authority_ids, days_since_issuance):
    """
    Find certificates issued by given authorities in last days_since_issuance number of days, that are still valid,
    not replaced, have auto-rotation ON.

    :param authority_ids: list of authority ids
    :param days_since_issuance: If not none, include certificates issued in only last days_since_issuance days
    :return: List of certificates matching the criteria
    """

    now = arrow.now().format("YYYY-MM-DD")
    query = database.session_query(Certificate)\
        .filter(Certificate.authority_id.in_(authority_ids))\
        .filter(Certificate.not_after >= now)\
        .filter(Certificate.rotation == true())\
        .filter(not_(Certificate.replaced.any()))

    if days_since_issuance:
        issuance_window = (
            arrow.now().shift(days=-days_since_issuance).format("YYYY-MM-DD")
        )
        query = query.filter(Certificate.date_created >= issuance_window)

    return query.all()


def get_certificates_with_same_cn_with_rotate_on(cn, date_created):
    """
    Find certificates with given common name created on date_created that are still valid, not replaced and marked for
    auto-rotate

    :param cn: common name to match
    :param date_created: creation date
    :return: List of certificates matching the criteria
    """
    now = arrow.now().format("YYYY-MM-DD")
    date_created_min = date_created.floor('day')
    date_created_max = date_created.ceil('day')

    query = database.session_query(Certificate)\
        .filter(Certificate.cn.like(cn))\
        .filter(Certificate.rotation == true())\
        .filter(Certificate.not_after >= now)\
        .filter(Certificate.date_created >= date_created_min)\
        .filter(Certificate.date_created <= date_created_max)\
        .filter(not_(Certificate.replaced.any()))

    return query.all()


def export(cert, export_plugin):
    """
    Exports a certificate to the requested format. This format
    may be a binary format.

    :param export_plugin:
    :param cert:
    :return:
    """
    plugin = plugins.get(export_plugin["slug"])
    return plugin.export(
        cert.body, cert.chain, cert.private_key, export_plugin["pluginOptions"]
    )


def update(cert_id, **kwargs):
    """
    Updates a certificate
    :param cert_id:
    :return:
    """
    cert = get(cert_id)

    for key, value in kwargs.items():
        setattr(cert, key, value)

    return database.update(cert)


def cleanup_owner_roles_notification(owner_name, kwargs):
    kwargs["roles"] = [r for r in kwargs["roles"] if r.name != owner_name]
    notification_prefix = f"DEFAULT_{owner_name.split('@')[0].upper()}"
    kwargs["notifications"] = [n for n in kwargs["notifications"] if not n.label.startswith(notification_prefix)]


def update_switches(cert, notify_flag=None, rotation_flag=None):
    """
    Toggle notification and/or rotation values which are boolean
    :param notify_flag: new notify value
    :param rotation_flag: new rotation value
    :param cert: Certificate object to be updated
    :return:
    """
    if notify_flag is not None:  # check for None allows value of False to continue
        cert.notify = notify_flag
    if rotation_flag is not None:
        cert.rotation = rotation_flag
    return database.update(cert)


def update_owner(cert, new_cert_data):
    """
    Modify owner for certificate. Removes roles and notifications associated with prior owner.
    :param cert: Certificate object to be updated
    :param new_cert_data: Dictionary including cert fields to be updated (owner, notifications, roles).
    These values are set in CertificateEditInputSchema and are generated for the new owner.
    :return:
    """
    # remove all notifications and roles associated with old owner
    cert.roles = new_cert_data["roles"] + [r for r in cert.roles if r.name != cert.owner]
    notification_prefix = f"DEFAULT_{cert.owner.split('@')[0].upper()}"
    cert.notifications = new_cert_data["notifications"] + [n for n in cert.notifications if not n.label.startswith(notification_prefix)]

    cert.owner = new_cert_data["owner"]
    return database.update(cert)


def create_certificate_roles(**kwargs):
    # create a role for the owner and assign it
    owner_role = role_service.get_or_create(
        kwargs["owner"],
        description=f"Auto generated role based on owner: {kwargs['owner']}"
    )

    # ensure that the authority's owner is also associated with the certificate
    if kwargs.get("authority"):
        authority_owner_role = role_service.get_by_name(kwargs["authority"].owner)
        return [owner_role, authority_owner_role]

    return [owner_role]


def mint(**kwargs):
    """
    Minting is slightly different for each authority.
    Support for multiple authorities is handled by individual plugins.

    """
    authority = kwargs["authority"]

    issuer = plugins.get(authority.plugin_name)

    # allow the CSR to be specified by the user
    if not kwargs.get("csr"):
        csr, private_key = create_csr(**kwargs)
        csr_created.send(authority=authority, csr=csr)
    else:
        csr = str(kwargs.get("csr"))
        private_key = None
        csr_imported.send(authority=authority, csr=csr)

    cert_body, cert_chain, external_id = issuer.create_certificate(csr, kwargs)
    return cert_body, private_key, cert_chain, external_id, csr


def import_certificate(**kwargs):
    """
    Uploads already minted certificates and pulls the required information into Lemur.

    This is to be used for certificates that are created outside of Lemur but
    should still be tracked.

    Internally this is used to bootstrap Lemur with external
    certificates, and used when certificates are 'discovered' through various discovery
    techniques. was still in aws.

    :param kwargs:
    """
    if not kwargs.get("owner"):
        kwargs["owner"] = current_app.config.get("LEMUR_SECURITY_TEAM_EMAIL")[0]

    return upload(**kwargs)


def upload(**kwargs):
    """
    Allows for pre-made certificates to be imported into Lemur.
    """
    roles = create_certificate_roles(**kwargs)

    if not kwargs.get("roles"):
        kwargs["roles"] = []
    kwargs["roles"] += [role for role in roles if role not in kwargs["roles"]]

    cert = Certificate(**kwargs)
    cert.authority = kwargs.get("authority")
    cert = database.create(cert)

    kwargs["creator"].certificates.append(cert)

    cert = database.update(cert)
    certificate_imported.send(certificate=cert, authority=cert.authority)
    return cert


def create(**kwargs):
    """
    Creates a new certificate.
    """
    if "destinations" in kwargs:
        validate_no_duplicate_destinations(kwargs["destinations"])

    try:
        cert_body, private_key, cert_chain, external_id, csr = mint(**kwargs)
    except Exception:
        log_data = {
            "message": "Exception minting certificate",
            "issuer": kwargs["authority"].name,
            "cn": kwargs.get("common_name"),
            "san": ",".join(
                str(x.value) for x in kwargs["extensions"]["sub_alt_names"]["names"]
            ),
        }
        current_app.logger.error(log_data, exc_info=True)
        capture_exception()
        raise
    kwargs["body"] = cert_body
    kwargs["private_key"] = private_key
    kwargs["chain"] = cert_chain
    kwargs["external_id"] = external_id
    kwargs["csr"] = csr

    roles = create_certificate_roles(**kwargs)

    if kwargs.get("roles"):
        kwargs["roles"] += roles
    else:
        kwargs["roles"] = roles

    if cert_body:
        cert = Certificate(**kwargs)
        kwargs["creator"].certificates.append(cert)
    else:
        # ACME path
        cert = PendingCertificate(**kwargs)
        kwargs["creator"].pending_certificates.append(cert)

    cert.authority = kwargs["authority"]

    database.commit()

    if isinstance(cert, Certificate):
        certificate_issued.send(certificate=cert, authority=cert.authority)
        metrics.send(
            "certificate_issued",
            "counter",
            1,
            metric_tags=dict(owner=cert.owner, issuer=cert.issuer),
        )
        log_data = {
            "function": "lemur.certificates.service.create",
            "owner": cert.owner,
            "name": cert.name,
            "serial": cert.serial,
            "issuer": cert.issuer,
            "not_after": cert.not_after.format('YYYY-MM-DD HH:mm:ss'),
            "not_before": cert.not_before.format('YYYY-MM-DD HH:mm:ss'),
            "sans": str(', '.join([domain.name for domain in cert.domains])),
        }
        current_app.logger.info(log_data)

    if isinstance(cert, PendingCertificate):
        # We need to refresh the pending certificate to avoid "Instance is not bound to a Session; "
        # "attribute refresh operation cannot proceed"
        pending_cert = database.session_query(PendingCertificate).get(cert.id)
        from lemur.common.celery import fetch_acme_cert

        if not current_app.config.get("ACME_DISABLE_AUTORESOLVE", False):
            fetch_acme_cert.apply_async((pending_cert.id, kwargs.get("async_reissue_notification_cert_id", None)), countdown=5)

    return cert


def validate_no_duplicate_destinations(destinations):
    """
    Validates destinations do not overlap accounts for the same plugin (for plugins that don't allow duplicates).
    """
    dest_plugin_accounts = {}
    for dest in destinations:
        plugin_accounts = dest_plugin_accounts.setdefault(dest.plugin_name, {})
        account = get_plugin_option("accountNumber", dest.options)
        dest_plugin = plugins.get(dest.plugin_name)
        if account in plugin_accounts and not dest_plugin.allow_multiple_per_account():
            raise Exception(f"Duplicate destinations for plugin {dest.plugin_name} and account {account} are not "
                            f"allowed")
        plugin_accounts[account] = True


def render(args):
    """
    Helper function that allows use to render our REST Api.

    :param args:
    :return:
    """
    query = database.session_query(Certificate)

    show_expired = args.pop("showExpired")
    if show_expired != 1:
        one_month_old = (
            arrow.now()
            .shift(months=current_app.config.get("HIDE_EXPIRED_CERTS_AFTER_MONTHS", -1))
            .format("YYYY-MM-DD")
        )
        query = query.filter(Certificate.not_after > one_month_old)

    time_range = args.pop("time_range")

    destination_id = args.pop("destination_id")
    notification_id = args.pop("notification_id", None)
    serial_number = args.pop("serial", None)
    show = args.pop("show")
    # owner = args.pop('owner')
    # creator = args.pop('creator')  # TODO we should enabling filtering by owner

    filt = args.pop("filter")

    if filt:
        terms = filt.split(";")
        term = f"%{terms[1]}%"
        # Exact matches for quotes. Only applies to name, issuer, and cn
        if terms[1].startswith('"') and terms[1].endswith('"'):
            term = terms[1][1:-1]

        if "issuer" in terms:
            # we can't rely on issuer being correct in the cert directly so we combine queries
            sub_query = (
                database.session_query(Authority.id)
                .filter(Authority.name.ilike(term))
                .subquery()
            )

            query = query.filter(
                or_(
                    Certificate.issuer.ilike(term),
                    Certificate.authority_id.in_(sub_query),
                )
            )

        elif "destination" in terms:
            query = query.filter(
                Certificate.destinations.any(Destination.id == terms[1])
            )
        elif "notify" in filt:
            query = query.filter(Certificate.notify == truthiness(terms[1]))
        elif "rotation" in filt:
            query = query.filter(Certificate.rotation == truthiness(terms[1]))
        elif "active" in filt:
            query = query.filter(Certificate.active == truthiness(terms[1]))
        elif "cn" in terms:
            query = query.filter(
                or_(
                    func.lower(Certificate.cn).like(term.lower()),
                    Certificate.id.in_(like_domain_query(term)),
                )
            )
        elif "id" in terms:
            query = query.filter(Certificate.id == cast(terms[1], Integer))
        elif "name" in terms:
            query = query.filter(
                or_(
                    func.lower(Certificate.name).like(term.lower()),
                    Certificate.id.in_(like_domain_query(term)),
                    func.lower(Certificate.cn).like(term.lower()),
                )
            )
        elif "fixedName" in terms:
            # only what matches the fixed name directly if a fixedname is provided
            query = query.filter(Certificate.name == terms[1])
        else:
            query = database.filter(query, Certificate, terms)

    if show:
        sub_query = (
            database.session_query(Role.name)
            .filter(Role.user_id == args["user"].id)
            .subquery()
        )
        query = query.filter(
            or_(
                Certificate.user_id == args["user"].id, Certificate.owner.in_(sub_query)
            )
        )

    if destination_id:
        query = query.filter(
            Certificate.destinations.any(Destination.id == destination_id)
        )

    if notification_id:
        query = query.filter(
            Certificate.notifications.any(Notification.id == notification_id)
        )

    if time_range:
        to = arrow.now().shift(weeks=+time_range).format("YYYY-MM-DD")
        now = arrow.now().format("YYYY-MM-DD")
        query = query.filter(Certificate.not_after <= to).filter(
            Certificate.not_after >= now
        )

    if current_app.config.get("ALLOW_CERT_DELETION", False):
        query = query.filter(Certificate.deleted == false())

    if serial_number:
        if serial_number.lower().startswith('0x'):
            serial_number = str(int(serial_number[2:], 16))
        elif ":" in serial_number:
            serial_number = str(int(serial_number.replace(':', ''), 16))

        query = query.filter(Certificate.serial == serial_number)

    result = database.sort_and_page(query, Certificate, args)
    return result


def like_domain_query(term):
    domain_query = database.session_query(Domain.id)
    domain_query = domain_query.filter(func.lower(Domain.name).like(term.lower()))
    assoc_query = database.session_query(CertificateAssociation.certificate_id)
    assoc_query = assoc_query.filter(CertificateAssociation.domain_id.in_(domain_query))
    return assoc_query


def query_name(certificate_name, args):
    """
    Helper function that queries for a certificate by name

    :param args:
    :return:
    """
    query = database.session_query(Certificate)
    query = query.filter(Certificate.name == certificate_name)
    result = database.sort_and_page(query, Certificate, args)
    return result


def query_common_name(common_name, args):
    """
    Helper function that queries for not expired certificates by common name,
    owner and san. Pagination is supported.

    :param common_name:
    :param args:
    :return:
    """
    owner = args.pop("owner")
    san = args.pop("san")
    page = args.pop("page")
    count = args.pop("count")

    paginate = page and count
    query = database.session_query(Certificate) if paginate else Certificate.query

    # only not expired certificates
    current_time = arrow.utcnow()
    query = query.filter(Certificate.not_after >= current_time.format("YYYY-MM-DD"))\
        .filter(not_(Certificate.revoked))\
        .filter(not_(Certificate.replaced.any()))  # ignore rotated certificates to avoid duplicates

    if owner:
        query = query.filter(Certificate.owner.ilike(owner))

    if common_name != "%":
        # if common_name is a wildcard ('%'), no need to include it in the query
        query = query.filter(Certificate.cn.ilike(common_name))

    if san and san != "%":
        # if san is a wildcard ('%'), no need to include it in the query
        query = query.filter(Certificate.id.in_(like_domain_query(san)))

    if paginate:
        args = {"page": page, "count": count, "sort_by": "id", "sort_dir": "desc"}
        return database.sort_and_page(query, Certificate, args)

    return query.all()


def get_ekus(csr: str):
    """Given a csr PEM, return the """
    csr_obj = x509.load_pem_x509_csr(csr.encode(), default_backend())
    return csr_obj.extensions.get_extension_for_class(x509.ExtendedKeyUsage)


def create_csr(**csr_config):
    """
    Given a list of domains create the appropriate csr
    for those domains

    :param csr_config:
    """
    private_key = generate_private_key(csr_config.get("key_type"))

    builder = x509.CertificateSigningRequestBuilder()
    name_list = []
    if current_app.config.get("LEMUR_OWNER_EMAIL_IN_SUBJECT", True):
        name_list.append(
            x509.NameAttribute(x509.OID_EMAIL_ADDRESS, csr_config["owner"])
        )
    if "common_name" in csr_config and csr_config["common_name"].strip():
        name_list.append(
            x509.NameAttribute(x509.OID_COMMON_NAME, csr_config["common_name"])
        )
    if "organization" in csr_config and csr_config["organization"].strip():
        name_list.append(
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, csr_config["organization"])
        )
    if (
        "organizational_unit" in csr_config
        and csr_config["organizational_unit"].strip()
    ):
        name_list.append(
            x509.NameAttribute(
                x509.OID_ORGANIZATIONAL_UNIT_NAME, csr_config["organizational_unit"]
            )
        )
    if "country" in csr_config and csr_config["country"].strip():
        name_list.append(
            x509.NameAttribute(x509.OID_COUNTRY_NAME, csr_config["country"])
        )
    if "state" in csr_config and csr_config["state"].strip():
        name_list.append(
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, csr_config["state"])
        )
    if "location" in csr_config and csr_config["location"].strip():
        name_list.append(
            x509.NameAttribute(x509.OID_LOCALITY_NAME, csr_config["location"])
        )
    builder = builder.subject_name(x509.Name(name_list))

    extensions = csr_config.get("extensions", {})
    critical_extensions = ["basic_constraints", "sub_alt_names", "key_usage"]
    noncritical_extensions = ["extended_key_usage"]
    for k, v in extensions.items():
        if v:
            if k in critical_extensions:
                current_app.logger.debug(
                    f"Adding Critical Extension: {k} {v}"
                )
                if k == "sub_alt_names":
                    if v["names"]:
                        builder = builder.add_extension(v["names"], critical=True)
                else:
                    builder = builder.add_extension(v, critical=True)

            if k in noncritical_extensions:
                current_app.logger.debug(f"Adding Extension: {k} {v}")
                builder = builder.add_extension(v, critical=False)

    ski = extensions.get("subject_key_identifier", {})
    if ski.get("include_ski", False):
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )

    request = builder.sign(private_key, hashes.SHA256(), default_backend())

    # serialize our private key and CSR
    private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # would like to use PKCS8 but AWS ELBs don't like it
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    csr = request.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

    return csr, private_key


def stats(**kwargs):
    """
    Helper that defines some useful statistics about certifications.

    :param kwargs:
    :return:
    """

    # Verify requested metric
    allow_list = ["bits", "issuer", "not_after", "signing_algorithm"]
    req_metric = kwargs.get("metric")
    if req_metric not in allow_list:
        raise Exception(
            f"Stats not available for requested metric: {req_metric}"
        )

    if req_metric == "not_after":
        start = arrow.utcnow()
        end = start.shift(weeks=+32)
        items = (
            database.db.session.query(Certificate.issuer, func.count(Certificate.id))
            .group_by(Certificate.issuer)
            .filter(Certificate.not_after <= end.format("YYYY-MM-DD"))
            .filter(Certificate.not_after >= start.format("YYYY-MM-DD"))
            .all()
        )

    else:
        attr = getattr(Certificate, req_metric)
        query = database.db.session.query(attr, func.count(attr))

        items = query.group_by(attr).all()

    keys = []
    values = []
    for key, count in items:
        keys.append(key)
        values.append(count)

    return {"labels": keys, "values": values}


def get_account_number(arn):
    """
    Extract the account number from an arn.

    :param arn: IAM SSL arn
    :return: account number associated with ARN
    """
    return arn.split(":")[4]


def get_name_from_arn(arn):
    """
    Extract the certificate name from an arn.

    :param arn: IAM SSL arn
    :return: name of the certificate as uploaded to AWS
    """
    return arn.split("/", 1)[1]


def calculate_reissue_range(start, end):
    """
    Determine what the new validity_start and validity_end dates should be.
    :param start:
    :param end:
    :return:
    """
    span = end - start

    new_start = arrow.utcnow()
    new_end = new_start + span

    return new_start, arrow.get(new_end)


def get_certificate_primitives(certificate):
    """
    Retrieve key primitive from a certificate such that the certificate
    could be recreated with new expiration or be used to build upon.
    :param certificate:
    :return: dict of certificate primitives, should be enough to effectively re-issue
    certificate via `create`.
    """
    start, end = calculate_reissue_range(certificate.not_before, certificate.not_after)
    ser = CertificateInputSchema().load(
        CertificateOutputSchema().dump(certificate).data
    )
    assert not ser.errors, "Error re-serializing certificate: %s" % ser.errors
    data = ser.data

    # we can't quite tell if we are using a custom name, as this is an automated process (typically)
    # we will rely on the Lemur generated name
    data.pop("name", None)

    # TODO this can be removed once we migrate away from cn
    data["cn"] = data["common_name"]

    # needed until we move off not_*
    data["not_before"] = start
    data["not_after"] = end
    data["validity_start"] = start
    data["validity_end"] = end
    return data


def reissue_certificate(certificate, notify=None, replace=None, user=None):
    """
    Reissue certificate with the same properties of the given certificate.
    :param certificate:
    :param notify:
    :param replace:
    :param user:
    :return:
    """
    primitives = get_certificate_primitives(certificate)

    if primitives.get("csr"):
        #  We do not want to re-use the CSR when creating a certificate because this defeats the purpose of rotation.
        del primitives["csr"]
    if not user:
        primitives["creator"] = certificate.user

    else:
        primitives["creator"] = user

    if replace:
        primitives["replaces"] = [certificate]

    # Modify description to include the certificate ID being reissued and mention that this is created by Lemur
    # as part of reissue
    reissue_message_prefix = "Reissued by Lemur for cert ID "
    reissue_message = re.compile(f"{reissue_message_prefix}([0-9]+)")
    if primitives["description"]:
        match = reissue_message.search(primitives["description"])
        if match:
            primitives["description"] = primitives["description"].replace(match.group(1), str(certificate.id))
        else:
            primitives["description"] = f"{reissue_message_prefix}{certificate.id}, {primitives['description']}"
    else:
        primitives["description"] = f"{reissue_message_prefix}{certificate.id}"

    # Rotate the certificate to ECCPRIME256V1 if cert owner is present in the configured list
    # This is a temporary change intending to rotate certificates to ECC, if opted in by certificate owners
    # Unless identified a use case, this will be removed in mid-Q2 2021
    ecc_reissue_owner_list = current_app.config.get("ROTATE_TO_ECC_OWNER_LIST", [])
    ecc_reissue_exclude_cn_list = current_app.config.get("ECC_NON_COMPATIBLE_COMMON_NAMES", [])

    if (certificate.owner in ecc_reissue_owner_list) and (certificate.cn not in ecc_reissue_exclude_cn_list):
        primitives["key_type"] = "ECCPRIME256V1"

    # allow celery to send notifications for PendingCertificates using the old cert
    if notify:
        primitives["async_reissue_notification_cert_id"] = certificate.id

    new_cert = create(**primitives)

    return new_cert


def is_attached_to_endpoint(certificate_name, endpoint_name):
    """
    Find if given certificate is attached to the endpoint. Both, certificate and endpoint, are identified by name.
    This method talks to elb and finds the real time information.
    :param certificate_name:
    :param endpoint_name:
    :return: True if certificate is attached to the given endpoint, False otherwise
    """
    endpoint = endpoint_service.get_by_name(endpoint_name)
    attached_certificates = endpoint.source.plugin.get_endpoint_certificate_names(endpoint)
    return certificate_name in attached_certificates


def remove_from_destination(certificate, destination):
    """
    Remove the certificate from given destination if clean() is implemented
    :param certificate:
    :param destination:
    :return:
    """
    plugin = plugins.get(destination.plugin_name)
    if not hasattr(plugin, "clean"):
        info_text = f"Cannot clean certificate {certificate.name}, {destination.plugin_name} plugin does not implement 'clean()'"
        current_app.logger.warning(info_text)
    else:
        plugin.clean(certificate=certificate, options=destination.options)


def deactivate(certificate):
    plugin = plugins.get(certificate.authority.plugin_name)
    return plugin.deactivate_certificate(certificate)


def revoke(certificate, reason):
    plugin = plugins.get(certificate.authority.plugin_name)
    plugin.revoke_certificate(certificate, reason)

    # Perform cleanup after revoke
    return cleanup_after_revoke(certificate)


def cleanup_after_revoke(certificate):
    """
    Perform the needed cleanup for a revoked certificate. This includes -
    1. Notify (if enabled)
    2. Disabling notification
    3. Disabling auto-rotation
    4. Update certificate status to 'revoked'
    5. Remove from AWS
    :param certificate: Certificate object to modify and update in DB
    :return: None
    """
    try:
        if certificate.notify:
            send_revocation_notification(certificate)
    except Exception:
        capture_exception()
        current_app.logger.warn(
            f"Error sending revocation notification for certificate: {certificate.name}", exc_info=True
        )

    certificate.notify = False
    certificate.rotation = False
    certificate.status = 'revoked'

    error_message = ""

    for destination in list(certificate.destinations):
        try:
            remove_from_destination(certificate, destination)
            certificate.destinations.remove(destination)
        except Exception as e:
            # This cleanup is the best-effort since certificate is already revoked at this point.
            # We will capture the exception and move on to the next destination
            capture_exception()
            error_message = error_message + f"Failed to remove destination: {destination.label}. {str(e)}. "

    database.update(certificate)
    return error_message


def get_issued_cert_count_for_authority(authority):
    """
    Returns the count of certs issued by the specified authority.

    :return:
    """
    return database.db.session.query(Certificate).filter(Certificate.authority_id == authority.id).count()


def get_all_valid_certificates_with_source(source_id):
    """
    Return list of certificates
    :param source_id:
    :return:
    """
    return (
        Certificate.query.filter(Certificate.sources.any(id=source_id))
        .filter(Certificate.revoked == false())
        .filter(Certificate.not_after >= arrow.now())
        .filter(not_(Certificate.replaced.any()))
        .all()
    )


def get_all_valid_certificates_with_destination(destination_id):
    """
    Return list of certificates
    :param destination_id:
    :return:
    """
    return (
        Certificate.query.filter(Certificate.destinations.any(id=destination_id))
        .filter(Certificate.revoked == false())
        .filter(Certificate.not_after >= arrow.now())
        .filter(not_(Certificate.replaced.any()))
        .all()
    )


def remove_source_association(certificate, source):
    certificate.sources.remove(source)
    database.update(certificate)

    metrics.send(
        "delete_certificate_source_association",
        "counter",
        1,
        metric_tags={"status": SUCCESS_METRIC_STATUS,
                     "source": source.label,
                     "certificate": certificate.name}
    )


def remove_destination_association(certificate, destination, clean=True):
    certificate.destinations.remove(destination)
    database.update(certificate)

    if clean:
        try:
            remove_from_destination(certificate, destination)
        except Exception as e:
            # This cleanup is the best-effort, it will capture the exception and log
            capture_exception()
            current_app.logger.warning(f"Failed to remove destination: {destination.label}. {str(e)}")

    metrics.send(
        "delete_certificate_destination_association",
        "counter",
        1,
        metric_tags={"status": SUCCESS_METRIC_STATUS,
                     "destination": destination.label,
                     "certificate": certificate.name}
    )


def identify_and_persist_expiring_deployed_certificates(exclude_domains, exclude_owners, commit,
                                                        timeout_seconds_per_network_call=1):
    """
    Finds all certificates expiring soon but are still being used for TLS at any domain with which they are associated.
    Identified ports will then be persisted on the certificate_associations row for the given cert/domain combo.

    Note that this makes actual TLS network calls in order to establish the "deployed" part of this check.
    """
    all_certs = defaultdict(dict)
    for c in get_certs_for_expiring_deployed_cert_check(exclude_domains, exclude_owners):
        domains_for_cert = find_and_persist_domains_where_cert_is_deployed(c, exclude_domains, commit,
                                                                           timeout_seconds_per_network_call)
        if len(domains_for_cert) > 0:
            all_certs[c] = domains_for_cert


def get_certs_for_expiring_deployed_cert_check(exclude_domains, exclude_owners):
    threshold_days = current_app.config.get("LEMUR_EXPIRING_DEPLOYED_CERT_THRESHOLD_DAYS", 14)
    max_not_after = arrow.utcnow().shift(days=+threshold_days).format("YYYY-MM-DD")

    q = (
        database.db.session.query(Certificate)
        .filter(Certificate.not_after <= max_not_after)
        .filter(Certificate.expired == false())
        .filter(Certificate.revoked == false())
        .filter(Certificate.in_rotation_window == true())
    )

    exclude_conditions = []
    if exclude_domains:
        for e in exclude_domains:
            exclude_conditions.append(~Certificate.name.ilike(f"%{e}%"))

        q = q.filter(and_(*exclude_conditions))

    if exclude_owners:
        for e in exclude_owners:
            exclude_conditions.append(~Certificate.owner.ilike(f"{e}"))

        q = q.filter(and_(*exclude_conditions))

    return windowed_query(q, Certificate.id, 10000)


def find_and_persist_domains_where_cert_is_deployed(certificate, excluded_domains, commit,
                                                    timeout_seconds_per_network_call):
    """
    Checks if the specified cert is still deployed. Returns a list of domains to which it's deployed.

    We use the serial number to identify that a certificate is identical. If there were multiple certificates
    issued for the same domain with identical serial numbers, this could return a false positive.

    Note that this checks *all* configured ports (specified in config LEMUR_PORTS_FOR_DEPLOYED_CERTIFICATE_CHECK)
    for all the domains in the cert. If the domain is valid but the port is not, we have to wait for the connection
    to time out, which means this can be quite slow.

    :return: A dictionary of the form {'domain1': [ports], 'domain2': [ports]}
    """
    matched_domains = defaultdict(list)
    # filter out wildcards, we can't check them
    for cert_association in [assoc for assoc in certificate.certificate_associations if '*' not in assoc.domain.name]:
        domain_name = cert_association.domain.name
        # skip this domain if excluded
        if not any(excluded in domain_name for excluded in excluded_domains):
            matched_ports_for_domain = []
            for port in current_app.config.get("LEMUR_PORTS_FOR_DEPLOYED_CERTIFICATE_CHECK", [443]):
                start_time = time.time()
                status = FAILURE_METRIC_STATUS
                match = False
                try:
                    parsed_serial = parse_serial(get_certificate_via_tls(domain_name, port,
                                                                         timeout_seconds_per_network_call))
                    if parsed_serial == int(certificate.serial):
                        matched_ports_for_domain.append(port)
                        match = True
                        current_app.logger.warning(f'Identified expiring deployed certificate {certificate.name} '
                                                   f'at domain {domain_name} on port {port}')
                    status = SUCCESS_METRIC_STATUS
                except Exception:
                    current_app.logger.info(f'Unable to check certificate for domain {domain_name} on port {port}',
                                            exc_info=True)
                elapsed = int(round(1000 * (time.time() - start_time)))
                metrics.send("deployed_certificate_check", "TIMER", elapsed,
                             metric_tags={"certificate": certificate.name,
                                          "domain": domain_name,
                                          "port": port,
                                          "status": status,
                                          "match": match})
            matched_domains[domain_name] = matched_ports_for_domain
            if commit:
                # Update the DB
                cert_association.ports = matched_ports_for_domain
                database.commit()
    return matched_domains


def get_expiring_deployed_certificates(exclude=None):
    """
    Finds all certificates that are eligible for deployed expiring cert notifications. Returns the set of domain/port
    pairs at which each certificate was identified as in use (deployed).

    Sample response:
        defaultdict(<class 'list'>,
            {'testowner2@example.com': [(Certificate(name=certificate100),
                                        defaultdict(<class 'list'>, {'localhost': [65521, 65522, 65523]}))],
            'testowner3@example.com': [(Certificate(name=certificate101),
                                        defaultdict(<class 'list'>, {'localhost': [65521, 65522, 65523]}))]})

    :return: A dictionary with owner as key, and a list of certificates associated with domains/ports.
    """
    certs_domains_and_ports = defaultdict(dict)
    for certificate in get_certs_for_expiring_deployed_cert_check(exclude, None):
        matched_domains = defaultdict(list)
        for cert_association in [assoc for assoc in certificate.certificate_associations if assoc.ports]:
            matched_domains[cert_association.domain.name] = cert_association.ports
        if len(matched_domains) > 0:
            certs_domains_and_ports[certificate] = matched_domains

    certs_domains_and_ports_by_owner = defaultdict(list)
    # group by owner
    for owner, owner_certs in groupby(sorted(certs_domains_and_ports.items(),
                                             key=lambda x: x[0].owner), lambda x: x[0].owner):
        certs_domains_and_ports_by_owner[owner] = list(owner_certs)
    return certs_domains_and_ports_by_owner


def allowed_issuance_for_domain(common_name, extensions):
    check_permission_for_cn = True if common_name else False

    # authorize issuance for every x509.DNSName SAN
    if extensions and extensions.get("sub_alt_names"):
        for san in extensions["sub_alt_names"]["names"]:
            if isinstance(san, x509.DNSName):
                if san.value == common_name:
                    check_permission_for_cn = False
                is_authorized_for_domain(san.value)

    # lemur UI copies CN as SAN (x509.DNSName). Permission check for CN might already be covered above.
    if check_permission_for_cn:
        is_authorized_for_domain(common_name)


def send_certificate_expiration_metrics(expiry_window=None):
    """
    Iterate over each certificate and emit a metric for how many days until expiration.

    :param expiry_window: defines the window for cert filter, ex: 90 will only return certs expiring in the next 90 days.
    """
    success = failure = 0

    certificates = get_certificates_for_expiration_metrics(expiry_window)

    for certificate in certificates:
        try:
            days_until_expiration = _get_cert_expiry_in_days(certificate.not_after)
            has_active_endpoints = len(certificate.endpoints) > 0
            is_replacement = len(certificate.replaces) > 0

            metrics.send(
                "certificates.days_until_expiration",
                "gauge",
                days_until_expiration,
                metric_tags={
                    "cert_id": certificate.id,
                    "common_name": certificate.cn.replace("*", "star"),
                    "has_active_endpoints": has_active_endpoints,
                    "is_replacement": is_replacement
                }
            )
            success += 1
        except Exception as e:
            current_app.logger.warn(
                f"Error sending expiry metric for certificate: {certificate.name}", exc_info=True
            )
            failure += 1

    return success, failure


def get_certificates_for_expiration_metrics(expiry_window):
    """

    :param expiry_window: defines the window for cert filter, ex: 90 will only return certs expiring in the next 90 days.
    :return: list of certificates
    """
    filters = [
        Certificate.expired == false(),
        Certificate.revoked == false(),
        not_(Certificate.replaced.any())
    ]

    # if expiry_window param was passed in then get only certs within that window
    if expiry_window:
        filters.append(Certificate.not_after <= arrow.now().shift(days=expiry_window).format("YYYY-MM-DD"))

    return database.db.session.query(Certificate).filter(*filters)


def _get_cert_expiry_in_days(cert_not_after):
    time_until_expiration = arrow.get(cert_not_after) - arrow.utcnow()
    return time_until_expiration.days
