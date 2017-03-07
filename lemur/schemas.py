"""
.. module: lemur.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from sqlalchemy.orm.exc import NoResultFound

from marshmallow import fields, post_load, pre_load, post_dump
from marshmallow.exceptions import ValidationError

from lemur.common import validators
from lemur.common.schema import LemurSchema, LemurInputSchema, LemurOutputSchema
from lemur.common.fields import KeyUsageExtension, ExtendedKeyUsageExtension, BasicConstraintsExtension, SubjectAlternativeNameExtension

from lemur.plugins import plugins
from lemur.plugins.utils import get_plugin_option
from lemur.roles.models import Role
from lemur.users.models import User
from lemur.authorities.models import Authority
from lemur.certificates.models import Certificate
from lemur.destinations.models import Destination
from lemur.notifications.models import Notification


def validate_options(options):
    """
    Ensures that the plugin options are valid.
    :param options:
    :return:
    """
    interval = get_plugin_option('interval', options)
    unit = get_plugin_option('unit', options)

    if not interval and not unit:
        return

    if interval == 'month':
        unit *= 30

    elif interval == 'week':
        unit *= 7

    if unit > 90:
        raise ValidationError('Notification cannot be more than 90 days into the future.')


def get_object_attribute(data, many=False):
    if many:
        ids = [d.get('id') for d in data]
        names = [d.get('name') for d in data]

        if None in ids:
            if None in names:
                raise ValidationError('Associated object require a name or id.')
            else:
                return 'name'
        return 'id'
    else:
        if data.get('id'):
            return 'id'
        elif data.get('name'):
            return 'name'
        else:
            raise ValidationError('Associated object require a name or id.')


def fetch_objects(model, data, many=False):
    attr = get_object_attribute(data, many=many)

    if many:
        values = [v[attr] for v in data]
        items = model.query.filter(getattr(model, attr).in_(values)).all()
        found = [getattr(i, attr) for i in items]
        diff = set(values).symmetric_difference(set(found))

        if diff:
            raise ValidationError('Unable to locate {model} with {attr} {diff}'.format(
                model=model,
                attr=attr,
                diff=",".join(list(diff))))

        return items

    else:
        try:
            return model.query.filter(getattr(model, attr) == data[attr]).one()
        except NoResultFound:
            raise ValidationError('Unable to find {model} with {attr}: {data}'.format(
                model=model,
                attr=attr,
                data=data[attr]))


class AssociatedAuthoritySchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        return fetch_objects(Authority, data, many=many)


class AssociatedRoleSchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        return fetch_objects(Role, data, many=many)


class AssociatedDestinationSchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        return fetch_objects(Destination, data, many=many)


class AssociatedNotificationSchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        return fetch_objects(Notification, data, many=many)


class AssociatedCertificateSchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        return fetch_objects(Certificate, data, many=many)


class AssociatedUserSchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        return fetch_objects(User, data, many=many)


class PluginInputSchema(LemurInputSchema):
    plugin_options = fields.List(fields.Dict(), validate=validate_options)
    slug = fields.String(required=True)
    title = fields.String()
    description = fields.String()

    @post_load
    def get_object(self, data, many=False):
        try:
            data['plugin_object'] = plugins.get(data['slug'])
            return data
        except Exception:
            raise ValidationError('Unable to find plugin: {0}'.format(data['slug']))


class PluginOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    label = fields.String()
    description = fields.String()
    active = fields.Boolean()
    options = fields.List(fields.Dict(), dump_to='pluginOptions')
    slug = fields.String()
    title = fields.String()


plugins_output_schema = PluginOutputSchema(many=True)
plugin_output_schema = PluginOutputSchema


class BaseExtensionSchema(LemurSchema):
    @pre_load(pass_many=True)
    def preprocess(self, data, many):
        return self.under(data, many=many)

    @post_dump(pass_many=True)
    def post_process(self, data, many):
        if data:
            data = self.camel(data, many=many)
        return data


class AuthorityKeyIdentifierSchema(BaseExtensionSchema):
    use_key_identifier = fields.Boolean()
    use_authority_cert = fields.Boolean()


class CertificateInfoAccessSchema(BaseExtensionSchema):
    include_aia = fields.Boolean()

    @post_dump
    def handle_keys(self, data):
        return {'includeAIA': data['include_aia']}


class SubjectKeyIdentifierSchema(BaseExtensionSchema):
    include_ski = fields.Boolean()

    @post_dump
    def handle_keys(self, data):
        return {'includeSKI': data['include_ski']}


class CustomOIDSchema(BaseExtensionSchema):
    oid = fields.String()
    encoding = fields.String(validate=validators.encoding)
    value = fields.String()
    is_critical = fields.Boolean()


class NamesSchema(BaseExtensionSchema):
    names = SubjectAlternativeNameExtension()


class ExtensionSchema(BaseExtensionSchema):
    basic_constraints = BasicConstraintsExtension(missing={'ca': False})
    key_usage = KeyUsageExtension()
    extended_key_usage = ExtendedKeyUsageExtension()
    subject_key_identifier = fields.Nested(SubjectKeyIdentifierSchema)
    sub_alt_names = fields.Nested(NamesSchema)
    authority_key_identifier = fields.Nested(AuthorityKeyIdentifierSchema)
    certificate_info_access = fields.Nested(CertificateInfoAccessSchema)
    # FIXME: Convert custom OIDs to a custom field in fields.py like other Extensions
    # FIXME: Remove support in UI for Critical custom extensions https://github.com/Netflix/lemur/issues/665
    custom = fields.List(fields.Nested(CustomOIDSchema))


class EndpointNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    description = fields.String()
    name = fields.String()
    dnsname = fields.String()
    owner = fields.Email()
    type = fields.String()
    active = fields.Boolean()
