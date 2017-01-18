"""
.. module: lemur.authorities.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app

from marshmallow import fields, validates_schema, pre_load
from marshmallow import validate
from marshmallow.exceptions import ValidationError

from lemur.schemas import PluginInputSchema, PluginOutputSchema, ExtensionSchema, AssociatedAuthoritySchema, AssociatedRoleSchema
from lemur.users.schemas import UserNestedOutputSchema
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.common import validators, missing

from lemur.common.fields import ArrowDateTime


class AuthorityInputSchema(LemurInputSchema):
    name = fields.String(required=True)
    owner = fields.Email(required=True)
    description = fields.String()
    common_name = fields.String(required=True, validate=validators.sensitive_domain)

    validity_start = ArrowDateTime()
    validity_end = ArrowDateTime()
    validity_years = fields.Integer()

    # certificate body fields
    organizational_unit = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_ORGANIZATIONAL_UNIT'))
    organization = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_ORGANIZATION'))
    location = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_LOCATION'))
    country = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_COUNTRY'))
    state = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_STATE'))

    plugin = fields.Nested(PluginInputSchema)

    # signing related options
    type = fields.String(validate=validate.OneOf(['root', 'subca']), missing='root')
    parent = fields.Nested(AssociatedAuthoritySchema)
    signing_algorithm = fields.String(validate=validate.OneOf(['sha256WithRSA', 'sha1WithRSA']), missing='sha256WithRSA')
    key_type = fields.String(validate=validate.OneOf(['RSA2048', 'RSA4096']), missing='RSA2048')
    key_name = fields.String()
    sensitivity = fields.String(validate=validate.OneOf(['medium', 'high']), missing='medium')
    serial_number = fields.Integer()
    first_serial = fields.Integer(missing=1)

    extensions = fields.Nested(ExtensionSchema)

    roles = fields.Nested(AssociatedRoleSchema(many=True))

    @validates_schema
    def validate_dates(self, data):
        validators.dates(data)

    @validates_schema
    def validate_subca(self, data):
        if data['type'] == 'subca':
            if not data.get('parent'):
                raise ValidationError("If generating a subca, parent 'authority' must be specified.")

    @pre_load
    def ensure_dates(self, data):
        return missing.convert_validity_years(data)


class AuthorityUpdateSchema(LemurInputSchema):
    owner = fields.Email(required=True)
    description = fields.String()
    active = fields.Boolean()
    roles = fields.Nested(AssociatedRoleSchema(many=True))


class RootAuthorityCertificateOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    active = fields.Boolean()
    bits = fields.Integer()
    body = fields.String()
    chain = fields.String()
    description = fields.String()
    name = fields.String()
    cn = fields.String()
    not_after = fields.DateTime()
    not_before = fields.DateTime()
    owner = fields.Email()
    status = fields.Boolean()
    user = fields.Nested(UserNestedOutputSchema)


class AuthorityOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    description = fields.String()
    name = fields.String()
    owner = fields.Email()
    plugin = fields.Nested(PluginOutputSchema)
    active = fields.Boolean()
    options = fields.Dict()
    roles = fields.List(fields.Nested(AssociatedRoleSchema))
    authority_certificate = fields.Nested(RootAuthorityCertificateOutputSchema)


class AuthorityNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    description = fields.String()
    name = fields.String()
    owner = fields.Email()
    plugin = fields.Nested(PluginOutputSchema)
    active = fields.Boolean()


authority_update_schema = AuthorityUpdateSchema()
authority_input_schema = AuthorityInputSchema()
authority_output_schema = AuthorityOutputSchema()
authorities_output_schema = AuthorityOutputSchema(many=True)
