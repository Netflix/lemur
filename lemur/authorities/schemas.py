"""
.. module: lemur.authorities.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app

from marshmallow import fields, validates_schema
from marshmallow import validate
from marshmallow.exceptions import ValidationError

from lemur.schemas import PluginInputSchema, ExtensionSchema, AssociatedAuthoritySchema, AssociatedRoleSchema
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.common import validators


class AuthorityInputSchema(LemurInputSchema):
    name = fields.String(required=True)
    owner = fields.Email(required=True)
    description = fields.String()
    common_name = fields.String(required=True, validate=validators.sensitive_domain)

    validity_start = fields.DateTime()
    validity_end = fields.DateTime()
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
    authority = fields.Nested(AssociatedAuthoritySchema)
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
            if not data.get('authority'):
                raise ValidationError("If generating a subca parent 'authority' must be specified.")


class AuthorityOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    name = fields.String()
    owner = fields.Email()
    not_before = fields.DateTime()
    not_after = fields.DateTime()
    plugin_name = fields.String()
    body = fields.String()
    chain = fields.String()
    active = fields.Boolean()
    options = fields.Dict()
    roles = fields.List(fields.Nested(AssociatedRoleSchema))


authority_input_schema = AuthorityInputSchema()
authority_output_schema = AuthorityOutputSchema()
authorities_output_schema = AuthorityOutputSchema(many=True)
