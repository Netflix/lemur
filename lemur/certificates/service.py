"""
.. module: lemur.certificate.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import arrow
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from flask import current_app
from sqlalchemy import func, or_, not_, cast, Integer

from lemur import database
from lemur.authorities.models import Authority
from lemur.certificates.models import Certificate
from lemur.certificates.schemas import CertificateOutputSchema, CertificateInputSchema
from lemur.common.utils import generate_private_key, truthiness
from lemur.destinations.models import Destination
from lemur.domains.models import Domain
from lemur.extensions import metrics, sentry, signals
from lemur.notifications.models import Notification
from lemur.pending_certificates.models import PendingCertificate
from lemur.plugins.base import plugins
from lemur.roles import service as role_service
from lemur.roles.models import Role

csr_created = signals.signal('csr_created', "CSR generated")
csr_imported = signals.signal('csr_imported', "CSR imported from external source")
certificate_issued = signals.signal('certificate_issued', "Authority issued a certificate")
certificate_imported = signals.signal('certificate_imported', "Certificate imported from external source")


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
    return database.get(Certificate, name, field='name')


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


def get_all_pending_cleaning(source):
    """
    Retrieves all certificates that are available for cleaning.

    :param source:
    :return:
    """
    return Certificate.query.filter(Certificate.sources.any(id=source.id)) \
        .filter(not_(Certificate.endpoints.any())).filter(Certificate.expired).all()


def get_all_pending_reissue():
    """
    Retrieves all certificates that need to be rotated.

    Must be X days from expiration, uses the certificates rotation
    policy to determine how many days from expiration the certificate must be
    for rotation to be pending.

    :return:
    """
    return Certificate.query.filter(Certificate.rotation == True) \
        .filter(not_(Certificate.replaced.any())) \
        .filter(Certificate.in_rotation_window == True).all()  # noqa


def find_duplicates(cert):
    """
    Finds certificates that already exist within Lemur. We do this by looking for
    certificate bodies that are the same. This is the most reliable way to determine
    if a certificate is already being tracked by Lemur.

    :param cert:
    :return:
    """
    if cert['chain']:
        return Certificate.query.filter_by(body=cert['body'].strip(), chain=cert['chain'].strip()).all()
    else:
        return Certificate.query.filter_by(body=cert['body'].strip(), chain=None).all()


def export(cert, export_plugin):
    """
    Exports a certificate to the requested format. This format
    may be a binary format.

    :param export_plugin:
    :param cert:
    :return:
    """
    plugin = plugins.get(export_plugin['slug'])
    return plugin.export(cert.body, cert.chain, cert.private_key, export_plugin['pluginOptions'])


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


def create_certificate_roles(**kwargs):
    # create an role for the owner and assign it
    owner_role = role_service.get_by_name(kwargs['owner'])

    if not owner_role:
        owner_role = role_service.create(
            kwargs['owner'],
            description="Auto generated role based on owner: {0}".format(kwargs['owner'])
        )

    # ensure that the authority's owner is also associated with the certificate
    if kwargs.get('authority'):
        authority_owner_role = role_service.get_by_name(kwargs['authority'].owner)
        return [owner_role, authority_owner_role]

    return [owner_role]


def mint(**kwargs):
    """
    Minting is slightly different for each authority.
    Support for multiple authorities is handled by individual plugins.

    """
    authority = kwargs['authority']

    issuer = plugins.get(authority.plugin_name)

    # allow the CSR to be specified by the user
    if not kwargs.get('csr'):
        csr, private_key = create_csr(**kwargs)
        csr_created.send(authority=authority, csr=csr)
    else:
        csr = str(kwargs.get('csr'))
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
    if not kwargs.get('owner'):
        kwargs['owner'] = current_app.config.get('LEMUR_SECURITY_TEAM_EMAIL')[0]

    return upload(**kwargs)


def upload(**kwargs):
    """
    Allows for pre-made certificates to be imported into Lemur.
    """
    roles = create_certificate_roles(**kwargs)

    if kwargs.get('roles'):
        kwargs['roles'] += roles
    else:
        kwargs['roles'] = roles

    cert = Certificate(**kwargs)
    cert.authority = kwargs.get('authority')
    cert = database.create(cert)

    kwargs['creator'].certificates.append(cert)

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
        current_app.logger.error("Exception minting certificate", exc_info=True)
        sentry.captureException()
        raise
    kwargs['body'] = cert_body
    kwargs['private_key'] = private_key
    kwargs['chain'] = cert_chain
    kwargs['external_id'] = external_id
    kwargs['csr'] = csr

    roles = create_certificate_roles(**kwargs)

    if kwargs.get('roles'):
        kwargs['roles'] += roles
    else:
        kwargs['roles'] = roles

    if cert_body:
        cert = Certificate(**kwargs)
        kwargs['creator'].certificates.append(cert)
    else:
        cert = PendingCertificate(**kwargs)
        kwargs['creator'].pending_certificates.append(cert)

    cert.authority = kwargs['authority']

    database.commit()

    if isinstance(cert, Certificate):
        certificate_issued.send(certificate=cert, authority=cert.authority)
        metrics.send('certificate_issued', 'counter', 1, metric_tags=dict(owner=cert.owner, issuer=cert.issuer))

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

    time_range = args.pop('time_range')
    destination_id = args.pop('destination_id')
    notification_id = args.pop('notification_id', None)
    show = args.pop('show')
    # owner = args.pop('owner')
    # creator = args.pop('creator')  # TODO we should enabling filtering by owner

    filt = args.pop('filter')

    if filt:
        terms = filt.split(';')
        term = '%{0}%'.format(terms[1])
        # Exact matches for quotes. Only applies to name, issuer, and cn
        if terms[1].startswith('"') and terms[1].endswith('"'):
            term = terms[1][1:-1]

        if 'issuer' in terms:
            # we can't rely on issuer being correct in the cert directly so we combine queries
            sub_query = database.session_query(Authority.id) \
                .filter(Authority.name.ilike(term)) \
                .subquery()

            query = query.filter(
                or_(
                    Certificate.issuer.ilike(term),
                    Certificate.authority_id.in_(sub_query)
                )
            )

        elif 'destination' in terms:
            query = query.filter(Certificate.destinations.any(Destination.id == terms[1]))
        elif 'notify' in filt:
            query = query.filter(Certificate.notify == truthiness(terms[1]))
        elif 'active' in filt:
            query = query.filter(Certificate.active == truthiness(terms[1]))
        elif 'cn' in terms:
            query = query.filter(
                or_(
                    Certificate.cn.ilike(term),
                    Certificate.domains.any(Domain.name.ilike(term))
                )
            )
        elif 'id' in terms:
            query = query.filter(Certificate.id == cast(terms[1], Integer))
        elif 'name' in terms:
            query = query.filter(
                or_(
                    Certificate.name.ilike(term),
                    Certificate.domains.any(Domain.name.ilike(term)),
                    Certificate.cn.ilike(term),
                )
            )
        else:
            query = database.filter(query, Certificate, terms)

    if show:
        sub_query = database.session_query(Role.name).filter(Role.user_id == args['user'].id).subquery()
        query = query.filter(
            or_(
                Certificate.user_id == args['user'].id,
                Certificate.owner.in_(sub_query)
            )
        )

    if destination_id:
        query = query.filter(Certificate.destinations.any(Destination.id == destination_id))

    if notification_id:
        query = query.filter(Certificate.notifications.any(Notification.id == notification_id))

    if time_range:
        to = arrow.now().replace(weeks=+time_range).format('YYYY-MM-DD')
        now = arrow.now().format('YYYY-MM-DD')
        query = query.filter(Certificate.not_after <= to).filter(Certificate.not_after >= now)

    if current_app.config.get('ALLOW_CERT_DELETION', False):
        query = query.filter(Certificate.deleted == False)  # noqa

    result = database.sort_and_page(query, Certificate, args)
    return result


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


def create_csr(**csr_config):
    """
    Given a list of domains create the appropriate csr
    for those domains

    :param csr_config:
    """
    private_key = generate_private_key(csr_config.get('key_type'))

    builder = x509.CertificateSigningRequestBuilder()
    name_list = [x509.NameAttribute(x509.OID_COMMON_NAME, csr_config['common_name'])]
    if current_app.config.get('LEMUR_OWNER_EMAIL_IN_SUBJECT', True):
        name_list.append(x509.NameAttribute(x509.OID_EMAIL_ADDRESS, csr_config['owner']))
    if 'organization' in csr_config and csr_config['organization'].strip():
        name_list.append(x509.NameAttribute(x509.OID_ORGANIZATION_NAME, csr_config['organization']))
    if 'organizational_unit' in csr_config and csr_config['organizational_unit'].strip():
        name_list.append(x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, csr_config['organizational_unit']))
    if 'country' in csr_config and csr_config['country'].strip():
        name_list.append(x509.NameAttribute(x509.OID_COUNTRY_NAME, csr_config['country']))
    if 'state' in csr_config and csr_config['state'].strip():
        name_list.append(x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, csr_config['state']))
    if 'location' in csr_config and csr_config['location'].strip():
        name_list.append(x509.NameAttribute(x509.OID_LOCALITY_NAME, csr_config['location']))
    builder = builder.subject_name(x509.Name(name_list))

    extensions = csr_config.get('extensions', {})
    critical_extensions = ['basic_constraints', 'sub_alt_names', 'key_usage']
    noncritical_extensions = ['extended_key_usage']
    for k, v in extensions.items():
        if v:
            if k in critical_extensions:
                current_app.logger.debug('Adding Critical Extension: {0} {1}'.format(k, v))
                if k == 'sub_alt_names':
                    if v['names']:
                        builder = builder.add_extension(v['names'], critical=True)
                else:
                    builder = builder.add_extension(v, critical=True)

            if k in noncritical_extensions:
                current_app.logger.debug('Adding Extension: {0} {1}'.format(k, v))
                builder = builder.add_extension(v, critical=False)

    ski = extensions.get('subject_key_identifier', {})
    if ski.get('include_ski', False):
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )

    request = builder.sign(
        private_key, hashes.SHA256(), default_backend()
    )

    # serialize our private key and CSR
    private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # would like to use PKCS8 but AWS ELBs don't like it
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    csr = request.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode('utf-8')

    return csr, private_key


def stats(**kwargs):
    """
    Helper that defines some useful statistics about certifications.

    :param kwargs:
    :return:
    """
    if kwargs.get('metric') == 'not_after':
        start = arrow.utcnow()
        end = start.replace(weeks=+32)
        items = database.db.session.query(Certificate.issuer, func.count(Certificate.id)) \
            .group_by(Certificate.issuer) \
            .filter(Certificate.not_after <= end.format('YYYY-MM-DD')) \
            .filter(Certificate.not_after >= start.format('YYYY-MM-DD')).all()

    else:
        attr = getattr(Certificate, kwargs.get('metric'))
        query = database.db.session.query(attr, func.count(attr))

        items = query.group_by(attr).all()

    keys = []
    values = []
    for key, count in items:
        keys.append(key)
        values.append(count)

    return {'labels': keys, 'values': values}


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
    ser = CertificateInputSchema().load(CertificateOutputSchema().dump(certificate).data)
    assert not ser.errors, "Error re-serializing certificate: %s" % ser.errors
    data = ser.data

    # we can't quite tell if we are using a custom name, as this is an automated process (typically)
    # we will rely on the Lemur generated name
    data.pop('name', None)

    # TODO this can be removed once we migrate away from cn
    data['cn'] = data['common_name']

    # needed until we move off not_*
    data['not_before'] = start
    data['not_after'] = end
    data['validity_start'] = start
    data['validity_end'] = end
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
        primitives['creator'] = certificate.user

    else:
        primitives['creator'] = user

    if replace:
        primitives['replaces'] = [certificate]

    new_cert = create(**primitives)

    return new_cert
