"""
.. module: lemur.certificate.service
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import arrow
from datetime import timedelta

from flask import current_app
from sqlalchemy import func, or_

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from lemur import database
from lemur.extensions import metrics
from lemur.plugins.base import plugins
from lemur.common.utils import generate_private_key

from lemur.roles.models import Role
from lemur.domains.models import Domain
from lemur.authorities.models import Authority
from lemur.destinations.models import Destination
from lemur.certificates.models import Certificate
from lemur.notifications.models import Notification

from lemur.roles import service as role_service


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


def get_by_source(source_label):
    """
    Retrieves all certificates from a given source.

    :param source_label:
    :return:
    """
    return Certificate.query.filter(Certificate.sources.any(label=source_label))


def get_all_pending_rotation():
    """
    Retrieves all certificates that need to be rotated.

    Must be X days from expiration, uses `LEMUR_DEFAULT_ROTATION_INTERVAL`
    to determine how many days from expiration the certificate must be
    for rotation to be pending.

    :return:
    """
    now = arrow.utcnow()
    interval = current_app.config.get('LEMUR_DEFAULT_ROTATION_INTERVAL', 30)
    end = now + timedelta(days=interval)

    return Certificate.query.filter(Certificate.rotation == True)\
        .filter(Certificate.not_after <= end.format('YYYY-MM-DD')).all()  # noqa


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


def update(cert_id, owner, description, notify, destinations, notifications, replaces, roles):
    """
    Updates a certificate
    :param cert_id:
    :param owner:
    :param description:
    :param notify:
    :param destinations:
    :param notifications:
    :param replaces:
    :return:
    """
    cert = get(cert_id)
    cert.notify = notify
    cert.description = description
    cert.destinations = destinations
    cert.notifications = notifications
    cert.roles = roles
    cert.replaces = replaces
    cert.owner = owner

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
    else:
        csr = str(kwargs.get('csr'))
        private_key = None

    cert_body, cert_chain = issuer.create_certificate(csr, kwargs)
    return cert_body, private_key, cert_chain,


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

    if kwargs.get('private_key'):
        private_key = kwargs['private_key']
        if not isinstance(private_key, bytes):
            kwargs['private_key'] = private_key.encode('utf-8')

    cert = Certificate(**kwargs)

    cert = database.create(cert)

    kwargs['creator'].certificates.append(cert)
    return database.update(cert)


def create(**kwargs):
    """
    Creates a new certificate.
    """
    cert_body, private_key, cert_chain = mint(**kwargs)
    kwargs['body'] = cert_body
    kwargs['private_key'] = private_key
    kwargs['chain'] = cert_chain

    roles = create_certificate_roles(**kwargs)

    if kwargs.get('roles'):
        kwargs['roles'] += roles
    else:
        kwargs['roles'] = roles

    cert = Certificate(**kwargs)

    kwargs['creator'].certificates.append(cert)
    cert.authority = kwargs['authority']
    database.commit()

    metrics.send('certificate_issued', 'counter', 1, metric_tags=dict(owner=cert.owner, issuer=cert.issuer))
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

        if 'issuer' in terms:
            # we can't rely on issuer being correct in the cert directly so we combine queries
            sub_query = database.session_query(Authority.id)\
                .filter(Authority.name.ilike('%{0}%'.format(terms[1])))\
                .subquery()

            query = query.filter(
                or_(
                    Certificate.issuer.ilike('%{0}%'.format(terms[1])),
                    Certificate.authority_id.in_(sub_query)
                )
            )
            return database.sort_and_page(query, Certificate, args)

        elif 'destination' in terms:
            query = query.filter(Certificate.destinations.any(Destination.id == terms[1]))
        elif 'active' in filt:
            query = query.filter(Certificate.active == terms[1])
        elif 'cn' in terms:
            query = query.filter(
                or_(
                    Certificate.cn.ilike('%{0}%'.format(terms[1])),
                    Certificate.domains.any(Domain.name.ilike('%{0}%'.format(terms[1])))
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

    return database.sort_and_page(query, Certificate, args)


def create_csr(**csr_config):
    """
    Given a list of domains create the appropriate csr
    for those domains

    :param csr_config:
    """

    private_key = generate_private_key(csr_config.get('key_type'))

    # TODO When we figure out a better way to validate these options they should be parsed as str
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(x509.OID_COMMON_NAME, csr_config['common_name']),
        x509.NameAttribute(x509.OID_ORGANIZATION_NAME, csr_config['organization']),
        x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, csr_config['organizational_unit']),
        x509.NameAttribute(x509.OID_COUNTRY_NAME, csr_config['country']),
        x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, csr_config['state']),
        x509.NameAttribute(x509.OID_LOCALITY_NAME, csr_config['location']),
        x509.NameAttribute(x509.OID_EMAIL_ADDRESS, csr_config['owner'])
    ]))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    if csr_config.get('extensions'):
        for k, v in csr_config.get('extensions', {}).items():
            if k == 'sub_alt_names':
                # map types to their x509 objects
                general_names = []
                for name in v['names']:
                    if name['name_type'] == 'DNSName':
                        general_names.append(x509.DNSName(name['value']))

                builder = builder.add_extension(
                    x509.SubjectAlternativeName(general_names), critical=True
                )

    # TODO support more CSR options, none of the authority plugins currently support these options
    #    builder.add_extension(
    #        x509.KeyUsage(
    #            digital_signature=digital_signature,
    #            content_commitment=content_commitment,
    #            key_encipherment=key_enipherment,
    #            data_encipherment=data_encipherment,
    #            key_agreement=key_agreement,
    #            key_cert_sign=key_cert_sign,
    #            crl_sign=crl_sign,
    #            encipher_only=enchipher_only,
    #            decipher_only=decipher_only
    #        ), critical=True
    #    )
    #
    #    # we must maintain our own list of OIDs here
    #    builder.add_extension(
    #        x509.ExtendedKeyUsage(
    #            server_authentication=server_authentication,
    #            email=
    #        )
    #    )
    #
    #    builder.add_extension(
    #        x509.AuthorityInformationAccess()
    #    )
    #
    #    builder.add_extension(
    #        x509.AuthorityKeyIdentifier()
    #    )
    #
    #    builder.add_extension(
    #        x509.SubjectKeyIdentifier()
    #    )
    #
    #    builder.add_extension(
    #        x509.CRLDistributionPoints()
    #    )
    #
    #    builder.add_extension(
    #        x509.ObjectIdentifier(oid)
    #    )

    request = builder.sign(
        private_key, hashes.SHA256(), default_backend()
    )

    # serialize our private key and CSR
    private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # would like to use PKCS8 but AWS ELBs don't like it
        encryption_algorithm=serialization.NoEncryption()
    )

    if isinstance(private_key, bytes):
        private_key = private_key.decode('utf-8')

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
        items = database.db.session.query(Certificate.issuer, func.count(Certificate.id))\
            .group_by(Certificate.issuer)\
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
    names = [{'name_type': 'DNSName', 'value': x.name} for x in certificate.domains]

    # TODO pull additional extensions
    extensions = {
        'sub_alt_names': {
            'names': names
        }
    }

    return dict(
        authority=certificate.authority,
        common_name=certificate.cn,
        description=certificate.description,
        validity_start=start,
        validity_end=end,
        destinations=certificate.destinations,
        roles=certificate.roles,
        extensions=extensions,
        owner=certificate.owner,
        organization=certificate.organization,
        organizational_unit=certificate.organizational_unit,
        country=certificate.country,
        state=certificate.state,
        location=certificate.location,
        key_type=certificate.key_type,
        notifications=certificate.notifications
    )


def reissue_certificate(certificate, replace=None, user=None):
    """
    Reissue certificate with the same properties of the given certificate.
    :param certificate:
    :param replace:
    :param user:
    :return:
    """
    primitives = get_certificate_primitives(certificate)

    if not user:
        primitives['creator'] = certificate.user
    else:
        primitives['creator'] = user

    if replace:
        primitives['replacements'] = [certificate]

    new_cert = create(**primitives)

    return new_cert
