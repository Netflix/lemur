import json
from datetime import date
from typing import List

from factory import Sequence, post_generation, SubFactory
from factory.alchemy import SQLAlchemyModelFactory
from factory.fuzzy import FuzzyChoice, FuzzyText, FuzzyDate, FuzzyInteger

from lemur.api_keys.models import ApiKey
from lemur.authorities.models import Authority
from lemur.certificates.models import Certificate
from lemur.database import db
from lemur.destinations.models import Destination
from lemur.dns_providers.models import DnsProvider
from lemur.endpoints.models import Policy, Endpoint
from lemur.notifications.models import Notification
from lemur.pending_certificates.models import PendingCertificate
from lemur.policies.models import RotationPolicy
from lemur.roles.models import Role
from lemur.sources.models import Source
from lemur.users.models import User
from .vectors import (
    SAN_CERT_STR,
    SAN_CERT_KEY,
    CSR_STR,
    INTERMEDIATE_CERT_STR,
    ROOTCA_CERT_STR,
    INTERMEDIATE_KEY,
    WILDCARD_CERT_KEY,
    INVALID_CERT_STR,
)


class BaseFactory(SQLAlchemyModelFactory):
    """Base factory."""

    class Meta:
        """Factory configuration."""

        abstract = True
        sqlalchemy_session = db.session


class RotationPolicyFactory(BaseFactory):
    """Rotation Factory."""

    name = Sequence(lambda n: f"policy{n}")
    days = 30

    class Meta:
        """Factory configuration."""

        model = RotationPolicy


class CertificateFactory(BaseFactory):
    """Certificate factory."""

    name = Sequence(lambda n: f"certificate{n}")
    chain = INTERMEDIATE_CERT_STR
    body = SAN_CERT_STR
    private_key = SAN_CERT_KEY
    owner = "joe@example.com"
    status = FuzzyChoice(["valid", "revoked", "unknown"])
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


class InvalidCertificateFactory(CertificateFactory):
    body = INVALID_CERT_STR
    private_key = ""
    chain = ""


class AuthorityFactory(BaseFactory):
    """Authority factory."""

    name = Sequence(lambda n: f"authority{n}")
    owner = "joe@example.com"
    plugin = {"slug": "test-issuer"}
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

    name = Sequence(lambda n: f"authority{n}")
    owner = "joe@example.com"
    plugin = {"slug": "test-issuer-async"}
    description = FuzzyText(length=128)
    authority_certificate = SubFactory(CertificateFactory)


class CryptoAuthorityFactory(AuthorityFactory):
    """Authority factory based on 'cryptography' plugin."""

    plugin = {"slug": "cryptography-issuer"}


class OptionalCNAuthorityFactory(AuthorityFactory):
    """Optional CN Authority factory."""

    name = Sequence(lambda n: f"authority{n}")
    options = '[{"name": "cn_optional", "type": "boolean", "value":true, "helpMessage": "Define if CN is an optional input when issuing certificates"}]'


class DestinationFactory(BaseFactory):
    """Destination factory."""

    plugin_name = "test-destination"
    label = Sequence(lambda n: f"destination{n}")
    options = [{"name": "exportPlugin", "type": "export-plugin", "value": {"plugin_options": [{}]}},
               {"name": "accountNumber", "type": "str", "value": "1234567890"}]

    class Meta:
        """Factory Configuration."""

        model = Destination


class DuplicateAllowedDestinationFactory(BaseFactory):
    """Destination factory."""

    plugin_name = "test-destination-dupe-allowed"
    label = Sequence(lambda n: f"duplicate-allowed-destination{n}")
    options = [{"name": "exportPlugin", "type": "export-plugin", "value": {"plugin_options": [{}]}},
               {"name": "accountNumber", "type": "str", "value": "1234567890"}]

    class Meta:
        """Factory Configuration."""

        model = Destination


class SourceFactory(BaseFactory):
    """Source factory."""

    plugin_name = "test-source"
    label = Sequence(lambda n: f"source{n}")

    class Meta:
        """Factory Configuration."""

        model = Source


class NotificationFactory(BaseFactory):
    """Notification factory."""

    plugin_name = "test-notification"
    label = Sequence(lambda n: f"notification{n}")

    class Meta:
        """Factory Configuration."""

        model = Notification


class RoleFactory(BaseFactory):
    """Role factory."""

    name = Sequence(lambda n: f"role{n}")

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

    username = Sequence(lambda n: f"user{n}")
    email = Sequence(lambda n: f"user{n}@example.com")
    active = True
    password = FuzzyText(length=24)
    certificates: List[Certificate] = []

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

    @post_generation  # type: ignore
    def certificates(self, create, extracted, **kwargs):  # noqa: F811
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

    name = Sequence(lambda n: f"endpoint{n}")

    class Meta:
        """Factory Configuration."""

        model = Policy


class EndpointFactory(BaseFactory):
    """Endpoint Factory."""

    owner = "joe@example.com"
    name = Sequence(lambda n: f"endpoint{n}")
    type = FuzzyChoice(["elb"])
    active = True
    port = FuzzyInteger(0, high=65535)
    dnsname = "endpoint.example.com"
    policy = SubFactory(PolicyFactory)
    certificate = SubFactory(CertificateFactory)
    source = SubFactory(SourceFactory)

    class Meta:
        """Factory Configuration."""

        model = Endpoint


class ApiKeyFactory(BaseFactory):
    """Api Key Factory."""

    name = Sequence(lambda n: f"api_key_{n}")
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

    name = Sequence(lambda n: f"pending_certificate{n}")
    external_id = 12345
    csr = CSR_STR
    chain = INTERMEDIATE_CERT_STR
    private_key = WILDCARD_CERT_KEY
    owner = "joe@example.com"
    status = FuzzyChoice(["valid", "revoked", "unknown"])
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


class DnsProviderFactory(BaseFactory):
    """DnsProvider Factory."""

    name = Sequence(lambda n: f"dnsProvider{n}")
    description = FuzzyText(length=128)
    provider_type = FuzzyText(length=128)
    credentials = json.dumps({"account_id": f"{FuzzyInteger(100000, 999999).fuzz()}"})

    class Meta:
        """Factory Configuration."""

        model = DnsProvider
