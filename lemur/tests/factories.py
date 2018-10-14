
from datetime import date, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


from factory import Sequence, post_generation, SubFactory
from factory.alchemy import SQLAlchemyModelFactory
from factory.fuzzy import FuzzyChoice, FuzzyText, FuzzyDate, FuzzyInteger


from lemur.database import db
from lemur.authorities.models import Authority
from lemur.certificates.models import Certificate
from lemur.destinations.models import Destination
from lemur.sources.models import Source
from lemur.notifications.models import Notification
from lemur.pending_certificates.models import PendingCertificate
from lemur.users.models import User
from lemur.roles.models import Role
from lemur.endpoints.models import Policy, Endpoint
from lemur.policies.models import RotationPolicy
from lemur.api_keys.models import ApiKey

from .vectors import CSR_STR, INTERMEDIATE_CERT_STR, DEFAULT_SANS, \
    ROOTCA_CERT_STR, INTERMEDIATE_KEY, WILDCARD_CERT_KEY


class SignedCertificateFactory(object):

    by_serial = {}
    by_name = {}

    def __init__(self):
        pass

    @classmethod
    def allcerts(cls):
        return cls.by_serial

    @classmethod
    def get_by_serial(cls, serial):
        return cls.by_serial[serial] if cls.by_serial.get(serial) else None

    @classmethod
    def get(cls, name, **kwargs):

        if name in cls.by_name:
            return cls.by_name[name]

        c = SignedCertificate(name, **kwargs)
        cls.by_serial[c.serial] = c
        cls.by_name[name] = c
        return c


class SignedCertificate(object):
    """ Autocreate Signed certs """

    def __init__(self, name, **kwargs):

        serial = kwargs['serial'] if kwargs.get('serial') else x509.random_serial_number()
        cacert = kwargs['cacert'] if kwargs.get('cacert') else INTERMEDIATE_CERT_STR
        cakey = kwargs['cakey'] if kwargs.get('cakey') else INTERMEDIATE_KEY
        sans = kwargs['sans'] if kwargs.get('sans') else DEFAULT_SANS

        self.name = name
        self.sans = [san for san in sans] if sans else []  # per rfc6125, add the CN
        self.serial = serial
        self.serial_name = hex(int(self.serial))[2:].upper()
        self.cacert = x509.load_pem_x509_certificate(bytes(cacert, 'utf8'), default_backend())
        self.cakey = serialization.load_pem_private_key(bytes(cakey, 'utf8'),
                                                        password=None,
                                                        backend=default_backend())

        not_before = kwargs['not_before'] if kwargs.get('not_before') else self.cacert.not_valid_before
        not_after = kwargs['not_after'] if kwargs.get('not_after') else self.cacert.not_valid_after

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        self.csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, name),
                    self.cacert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0],
                    self.cacert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0],
                    self.cacert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0],
                    self.cacert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0],
                    self.cacert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0],
                ]
            )).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(san) for san in self.sans]),
                critical=False,
        ).sign(self.private_key, hashes.SHA256(), default_backend())

        self.certificate = x509.CertificateBuilder(
            issuer_name=self.cacert.subject,
            subject_name=self.csr.subject,
            public_key=self.csr.public_key(),
            serial_number=self.serial,
            not_valid_before=not_before,
            not_valid_after=not_after
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san) for san in self.sans]),
            critical=False,
        ).sign(self.cakey, hashes.SHA256(), default_backend())

    def cert_pem(self):
        return self.certificate.public_bytes(Encoding.PEM).decode('utf-8')

    def key_pem(self):
        return self.private_key.private_bytes(Encoding.PEM,
                                              PrivateFormat.TraditionalOpenSSL,
                                              NoEncryption()).decode('utf-8')


class BaseFactory(SQLAlchemyModelFactory):
    """Base factory."""

    class Meta:
        """Factory configuration."""
        abstract = True
        sqlalchemy_session = db.session


class RotationPolicyFactory(BaseFactory):
    """Rotation Factory."""
    name = Sequence(lambda n: 'policy{0}'.format(n))
    days = 30

    class Meta:
        """Factory configuration."""
        model = RotationPolicy


class CertificateFactory(BaseFactory):
    """Certificate factory."""
    name = Sequence(lambda n: 'certificate{0}'.format(n))
    chain = INTERMEDIATE_CERT_STR
    body = Sequence(lambda n: SignedCertificateFactory.get('certificate{0}'.format(n)).cert_pem())
    private_key = Sequence(lambda n: SignedCertificateFactory.get('certificate{0}'.format(n)).key_pem())
    owner = 'joe@example.com'
    status = FuzzyChoice(['valid', 'revoked', 'unknown'])
    deleted = False
    description = FuzzyText(length=128)
    active = True
    date_created = FuzzyDate(date(2016, 1, 1), date(2020, 1, 1))
    rotation_policy = SubFactory(RotationPolicyFactory)

    class Meta:
        """Factory Configuration."""
        model = Certificate

    @post_generation
    def user(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            self.user_id = extracted.id

    @post_generation
    def authority(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            self.authority_id = extracted.id

    @post_generation
    def notifications(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for notification in extracted:
                self.notifications.append(notification)

    @post_generation
    def destinations(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for destination in extracted:
                self.destintations.append(destination)

    @post_generation
    def replaces(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for replace in extracted:
                self.replaces.append(replace)

    @post_generation
    def sources(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for source in extracted:
                self.sources.append(source)

    @post_generation
    def domains(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for domain in extracted:
                self.domains.append(domain)

    @post_generation
    def roles(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for domain in extracted:
                self.roles.append(domain)


class CACertificateFactory(CertificateFactory):
    chain = ROOTCA_CERT_STR
    body = INTERMEDIATE_CERT_STR
    private_key = INTERMEDIATE_KEY


class AuthorityFactory(BaseFactory):
    """Authority factory."""
    name = Sequence(lambda n: 'authority{0}'.format(n))
    owner = 'joe@example.com'
    plugin = {'slug': 'test-issuer'}
    description = FuzzyText(length=128)
    authority_certificate = SubFactory(CACertificateFactory)

    class Meta:
        """Factory configuration."""
        model = Authority

    @post_generation
    def roles(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for role in extracted:
                self.roles.append(role)


class AsyncAuthorityFactory(AuthorityFactory):
    """Async Authority factory."""
    name = Sequence(lambda n: 'authority{0}'.format(n))
    owner = 'joe@example.com'
    plugin = {'slug': 'test-issuer-async'}
    description = FuzzyText(length=128)
    authority_certificate = SubFactory(CertificateFactory)


class DestinationFactory(BaseFactory):
    """Destination factory."""
    plugin_name = 'test-destination'
    label = Sequence(lambda n: 'destination{0}'.format(n))

    class Meta:
        """Factory Configuration."""
        model = Destination


class SourceFactory(BaseFactory):
    """Source factory."""
    plugin_name = 'test-source'
    label = Sequence(lambda n: 'source{0}'.format(n))

    class Meta:
        """Factory Configuration."""
        model = Source


class NotificationFactory(BaseFactory):
    """Notification factory."""
    plugin_name = 'test-notification'
    label = Sequence(lambda n: 'notification{0}'.format(n))

    class Meta:
        """Factory Configuration."""
        model = Notification


class RoleFactory(BaseFactory):
    """Role factory."""
    name = Sequence(lambda n: 'role{0}'.format(n))

    class Meta:
        """Factory Configuration."""
        model = Role

    @post_generation
    def users(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for user in extracted:
                self.users.append(user)


class UserFactory(BaseFactory):
    """User Factory."""
    username = Sequence(lambda n: 'user{0}'.format(n))
    email = Sequence(lambda n: 'user{0}@example.com'.format(n))
    active = True
    password = FuzzyText(length=24)
    certificates = []

    class Meta:
        """Factory Configuration."""
        model = User

    @post_generation
    def roles(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for role in extracted:
                self.roles.append(role)

    @post_generation
    def certificates(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for cert in extracted:
                self.certificates.append(cert)

    @post_generation
    def authorities(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for authority in extracted:
                self.authorities.append(authority)


class PolicyFactory(BaseFactory):
    """Policy Factory."""
    name = Sequence(lambda n: 'endpoint{0}'.format(n))

    class Meta:
        """Factory Configuration."""
        model = Policy


class EndpointFactory(BaseFactory):
    """Endpoint Factory."""
    owner = 'joe@example.com'
    name = Sequence(lambda n: 'endpoint{0}'.format(n))
    type = FuzzyChoice(['elb'])
    active = True
    port = FuzzyInteger(0, high=65535)
    dnsname = 'endpoint.example.com'
    policy = SubFactory(PolicyFactory)
    certificate = SubFactory(CertificateFactory)
    source = SubFactory(SourceFactory)

    class Meta:
        """Factory Configuration."""
        model = Endpoint


class ApiKeyFactory(BaseFactory):
    """Api Key Factory."""
    name = Sequence(lambda n: 'api_key_{0}'.format(n))
    revoked = False
    ttl = -1
    issued_at = 1

    class Meta:
        """Factory Configuration."""
        model = ApiKey

    @post_generation
    def user(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            self.userId = extracted.id


class PendingCertificateFactory(BaseFactory):
    """PendingCertificate factory."""
    name = Sequence(lambda n: 'pending_certificate{0}'.format(n))
    external_id = 12345
    csr = CSR_STR
    chain = INTERMEDIATE_CERT_STR
    private_key = WILDCARD_CERT_KEY
    owner = 'joe@example.com'
    status = FuzzyChoice(['valid', 'revoked', 'unknown'])
    deleted = False
    description = FuzzyText(length=128)
    date_created = FuzzyDate(date(2016, 1, 1), date(2020, 1, 1))
    number_attempts = 0
    rename = False

    class Meta:
        """Factory Configuration."""
        model = PendingCertificate

    @post_generation
    def user(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            self.user_id = extracted.id

    @post_generation
    def authority(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            self.authority_id = extracted.id

    @post_generation
    def notifications(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for notification in extracted:
                self.notifications.append(notification)

    @post_generation
    def destinations(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for destination in extracted:
                self.destintations.append(destination)

    @post_generation
    def replaces(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for replace in extracted:
                self.replaces.append(replace)

    @post_generation
    def sources(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for source in extracted:
                self.sources.append(source)

    @post_generation
    def domains(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for domain in extracted:
                self.domains.append(domain)

    @post_generation
    def roles(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for domain in extracted:
                self.roles.append(domain)
