"""
.. module: lemur.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from marshmallow import fields, post_load, pre_load, post_dump, validates_schema

from lemur.roles.models import Role
from lemur.authorities.models import Authority
from lemur.destinations.models import Destination
from lemur.certificates.models import Certificate
from lemur.notifications.models import Notification

from lemur.common import validators
from lemur.common.schema import LemurSchema, LemurInputSchema

from lemur.plugins import plugins


class AssociatedAuthoritySchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        if data.get('id'):
            return Authority.query.filter(Authority.id == data['id']).one()
        elif data.get('name'):
            return Authority.query.filter(Authority.name == data['name']).one()


class AssociatedRoleSchema(LemurInputSchema):
    id = fields.Int(required=True)
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        if many:
            ids = [d['id'] for d in data]
            return Role.query.filter(Role.id.in_(ids)).all()
        else:
            return Role.query.filter(Role.id == data['id']).one()


class AssociatedDestinationSchema(LemurInputSchema):
    id = fields.Int(required=True)
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        if many:
            ids = [d['id'] for d in data]
            return Destination.query.filter(Destination.id.in_(ids)).all()
        else:
            return Destination.query.filter(Destination.id == data['id']).one()


class AssociatedNotificationSchema(LemurInputSchema):
    id = fields.Int(required=True)

    @post_load
    def get_object(self, data, many=False):
        if many:
            ids = [d['id'] for d in data]
            return Notification.query.filter(Notification.id.in_(ids)).all()
        else:
            return Notification.query.filter(Notification.id == data['id']).one()


class AssociatedCertificateSchema(LemurInputSchema):
    id = fields.Int(required=True)

    @post_load
    def get_object(self, data, many=False):
        if many:
            ids = [d['id'] for d in data]
            return Certificate.query.filter(Certificate.id.in_(ids)).all()
        else:
            return Certificate.query.filter(Certificate.id == data['id']).one()


class PluginSchema(LemurInputSchema):
    plugin_options = fields.Dict()
    slug = fields.String()
    title = fields.String()
    description = fields.String()

    @post_load
    def get_object(self, data, many=False):
        if many:
            return [plugins.get(plugin['slug']) for plugin in data]
        else:
            return plugins.get(data['slug'])


class BaseExtensionSchema(LemurSchema):
    @pre_load(pass_many=True)
    def preprocess(self, data, many):
        return self.under(data, many=many)

    @post_dump(pass_many=True)
    def post_process(self, data, many):
        if data:
            data = self.camel(data, many=many)
        return data


class BasicConstraintsSchema(BaseExtensionSchema):
    pass


class AuthorityIdentifierSchema(BaseExtensionSchema):
    use_authority_cert = fields.Boolean()


class AuthorityKeyIdentifierSchema(BaseExtensionSchema):
    use_key_identifier = fields.Boolean()


class CertificateInfoAccessSchema(BaseExtensionSchema):
    include_aia = fields.Boolean()

    @post_dump
    def handle_keys(self, data):
        return {'includeAIA': data['include_aia']}


class KeyUsageSchema(BaseExtensionSchema):
    use_crl_sign = fields.Boolean()
    use_data_encipherment = fields.Boolean()
    use_decipher_only = fields.Boolean()
    use_encipher_only = fields.Boolean()
    use_key_encipherment = fields.Boolean()
    use_digital_signature = fields.Boolean()
    use_non_repudiation = fields.Boolean()


class ExtendedKeyUsageSchema(BaseExtensionSchema):
    use_server_authentication = fields.Boolean()
    use_client_authentication = fields.Boolean()
    use_eap_over_lan = fields.Boolean()
    use_eap_over_ppp = fields.Boolean()
    use_ocsp_signing = fields.Boolean()
    use_smart_card_authentication = fields.Boolean()
    use_timestamping = fields.Boolean()


class SubjectKeyIdentifierSchema(BaseExtensionSchema):
    include_ski = fields.Boolean()

    @post_dump
    def handle_keys(self, data):
        return {'includeSKI': data['include_ski']}


class SubAltNameSchema(BaseExtensionSchema):
    name_type = fields.String(validate=validators.sub_alt_type)
    value = fields.String()

    @validates_schema
    def check_sensitive(self, data):
        if data['name_type'] == 'DNSName':
            validators.sensitive_domain(data['value'])


class SubAltNamesSchema(BaseExtensionSchema):
    names = fields.Nested(SubAltNameSchema, many=True)


class CustomOIDSchema(BaseExtensionSchema):
    oid = fields.String()
    oid_type = fields.String(validate=validators.oid_type)
    value = fields.String()


class ExtensionSchema(BaseExtensionSchema):
    basic_constraints = fields.Nested(BasicConstraintsSchema)
    key_usage = fields.Nested(KeyUsageSchema)
    extended_key_usage = fields.Nested(ExtendedKeyUsageSchema)
    subject_key_identifier = fields.Nested(SubjectKeyIdentifierSchema)
    sub_alt_names = fields.Nested(SubAltNamesSchema)
    authority_identifier = fields.Nested(AuthorityIdentifierSchema)
    authority_key_identifier = fields.Nested(AuthorityKeyIdentifierSchema)
    certificate_info_access = fields.Nested(CertificateInfoAccessSchema)
    custom = fields.List(fields.Nested(CustomOIDSchema))
