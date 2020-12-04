"""
.. module: lemur.certificate.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import arrow
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from flask import current_app
from sqlalchemy import func, or_, not_, cast, Integer
from sqlalchemy.sql.expression import false, true

from lemur import database
from lemur.authorities.models import Authority
from lemur.certificates.models import Certificate
from lemur.certificates.schemas import CertificateOutputSchema, CertificateInputSchema
from lemur.common.utils import generate_private_key, truthiness
from lemur.destinations.models import Destination
from lemur.domains.models import Domain
from lemur.endpoints import service as endpoint_service
from lemur.extensions import metrics, sentry, signals
from lemur.models import certificate_associations
from lemur.notifications.models import Notification
from lemur.pending_certificates.models import PendingCertificate
from lemur.plugins.base import plugins
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


def get_all_valid_certs(authority_plugin_name):
    """
    Retrieves all valid (not expired & not revoked) certificates within Lemur, for the given authority plugin names
    ignored if no authority_plugin_name provided.

    Note that depending on the DB size retrieving all certificates might an expensive operation

    :return:
    """
    if authority_plugin_name:
        return (
            Certificate.query.outerjoin(Authority, Authority.id == Certificate.authority_id).filter(
                Certificate.not_after > arrow.now().format("YYYY-MM-DD")).filter(
                Authority.plugin_name.in_(authority_plugin_name)).filter(Certificate.revoked.is_(False)).all()
        )
    else:
        return (
            Certificate.query.filter(Certificate.not_after > arrow.now().format("YYYY-MM-DD")).filter(
                Certificate.revoked.is_(False)).all()
        )


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


def update_notify(cert, notify_flag):
    """
    Toggle notification value which is a boolean
    :param notify_flag: new notify value
    :param cert: Certificate object to be updated
    :return:
    """
    cert.notify = notify_flag
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

    if kwargs.get("roles"):
        kwargs["roles"] += roles
    else:
        kwargs["roles"] = roles

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
    try:
        cert_body, private_key, cert_chain, external_id, csr = mint(**kwargs)
    except Exception:
        log_data = {
            "message": "Exception minting certificate",
            "issuer": kwargs["authority"].name,
            "cn": kwargs["common_name"],
        }
        current_app.logger.error(log_data, exc_info=True)
        sentry.captureException()
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

    if isinstance(cert, PendingCertificate):
        # We need to refresh the pending certificate to avoid "Instance is not bound to a Session; "
        # "attribute refresh operation cannot proceed"
        pending_cert = database.session_query(PendingCertificate).get(cert.id)
        from lemur.common.celery import fetch_acme_cert

        if not current_app.config.get("ACME_DISABLE_AUTORESOLVE", False):
            fetch_acme_cert.apply_async((pending_cert.id,), countdown=5)

    return cert


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
    show = args.pop("show")
    # owner = args.pop('owner')
    # creator = args.pop('creator')  # TODO we should enabling filtering by owner

    filt = args.pop("filter")

    if filt:
        terms = filt.split(";")
        term = "%{0}%".format(terms[1])
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

    result = database.sort_and_page(query, Certificate, args)
    return result


def like_domain_query(term):
    domain_query = database.session_query(Domain.id)
    domain_query = domain_query.filter(func.lower(Domain.name).like(term.lower()))
    assoc_query = database.session_query(certificate_associations.c.certificate_id)
    assoc_query = assoc_query.filter(certificate_associations.c.domain_id.in_(domain_query))
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
    Helper function that queries for not expired certificates by common name (and owner)

    :param common_name:
    :param args:
    :return:
    """
    owner = args.pop("owner")
    # only not expired certificates
    current_time = arrow.utcnow()

    query = Certificate.query.filter(Certificate.not_after >= current_time.format("YYYY-MM-DD"))\
        .filter(not_(Certificate.revoked))\
        .filter(not_(Certificate.replaced.any()))  # ignore rotated certificates to avoid duplicates

    if owner:
        query = query.filter(Certificate.owner.ilike(owner))

    if common_name != "%":
        # if common_name is a wildcard ('%'), no need to include it in the query
        query = query.filter(Certificate.cn.ilike(common_name))

    return query.all()


def create_csr(**csr_config):
    """
    Given a list of domains create the appropriate csr
    for those domains

    :param csr_config:
    """
    private_key = generate_private_key(csr_config.get("key_type"))

    builder = x509.CertificateSigningRequestBuilder()
    name_list = [x509.NameAttribute(x509.OID_COMMON_NAME, csr_config["common_name"])]
    if current_app.config.get("LEMUR_OWNER_EMAIL_IN_SUBJECT", True):
        name_list.append(
            x509.NameAttribute(x509.OID_EMAIL_ADDRESS, csr_config["owner"])
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
                    "Adding Critical Extension: {0} {1}".format(k, v)
                )
                if k == "sub_alt_names":
                    if v["names"]:
                        builder = builder.add_extension(v["names"], critical=True)
                else:
                    builder = builder.add_extension(v, critical=True)

            if k in noncritical_extensions:
                current_app.logger.debug("Adding Extension: {0} {1}".format(k, v))
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
    if kwargs.get("metric") == "not_after":
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
        attr = getattr(Certificate, kwargs.get("metric"))
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


def reissue_certificate(certificate, replace=None, user=None):
    """
    Reissue certificate with the same properties of the given certificate.
    :param certificate:
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


def revoke(certificate, reason):
    plugin = plugins.get(certificate.authority.plugin_name)
    plugin.revoke_certificate(certificate, reason)

    # Perform cleanup after revoke
    return cleanup_after_revoke(certificate)


def cleanup_after_revoke(certificate):
    """
    Perform the needed cleanup for a revoked certificate. This includes -
    1. Disabling notification
    2. Disabling auto-rotation
    3. Update certificate status to 'revoked'
    4. Remove from AWS
    :param certificate: Certificate object to modify and update in DB
    :return: None
    """
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
            sentry.captureException()
            error_message = error_message + f"Failed to remove destination: {destination.label}. {str(e)}. "

    database.update(certificate)
    return error_message


def get_issued_cert_count_for_authority(authority):
    """
    Returns the count of certs issued by the specified authority.

    :return:
    """
    return database.db.session.query(Certificate).filter(Certificate.authority_id == authority.id).count()
