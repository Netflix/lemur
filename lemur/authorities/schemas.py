"""
.. module: lemur.authorities.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from marshmallow import fields, validates_schema, pre_load
from marshmallow import validate
from marshmallow.exceptions import ValidationError

from lemur.common import validators, missing
from lemur.common.fields import ArrowDateTime
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.constants import CERTIFICATE_KEY_TYPES
from lemur.schemas import (
    PluginInputSchema,
    PluginOutputSchema,
    ExtensionSchema,
    AssociatedAuthoritySchema,
    AssociatedRoleSchema,
)
from lemur.users.schemas import UserNestedOutputSchema


class AuthorityInputSchema(LemurInputSchema):
    name = fields.String(required=True)
    owner = fields.Email(required=True)
    description = fields.String()
    common_name = fields.String(required=True, validate=validators.common_name)

    validity_start = ArrowDateTime()
    validity_end = ArrowDateTime()
    validity_years = fields.Integer()

    # certificate body fields
    organizational_unit = fields.String(
        missing=lambda: current_app.config.get("LEMUR_DEFAULT_ORGANIZATIONAL_UNIT")
    )
    organization = fields.String(
        missing=lambda: current_app.config.get("LEMUR_DEFAULT_ORGANIZATION")
    )
    location = fields.String(
        missing=lambda: current_app.config.get("LEMUR_DEFAULT_LOCATION")
    )
    country = fields.String(
        missing=lambda: current_app.config.get("LEMUR_DEFAULT_COUNTRY")
    )
    state = fields.String(missing=lambda: current_app.config.get("LEMUR_DEFAULT_STATE"))
    # Creating a String field instead of Email to allow empty value
    email = fields.String()

    plugin = fields.Nested(PluginInputSchema)

    # signing related options
    type = fields.String(validate=validate.OneOf(["root", "subca"]), missing="root")
    parent = fields.Nested(AssociatedAuthoritySchema)
    signing_algorithm = fields.String(
        validate=validate.OneOf(["sha256WithRSA", "sha1WithRSA",
                                 "sha256WithECDSA", "SHA384withECDSA", "SHA512withECDSA", "sha384WithECDSA",
                                 "sha512WithECDSA"]),
        missing="sha256WithRSA",
    )
    key_type = fields.String(
        validate=validate.OneOf(CERTIFICATE_KEY_TYPES), missing="RSA2048"
    )
    key_name = fields.String()
    sensitivity = fields.String(
        validate=validate.OneOf(["medium", "high"]), missing="medium"
    )
    serial_number = fields.Integer()
    first_serial = fields.Integer(missing=1)

    extensions = fields.Nested(ExtensionSchema)

    roles = fields.Nested(AssociatedRoleSchema(many=True))

    @validates_schema
    def validate_dates(self, data):
        validators.dates(data)

    @validates_schema
    def validate_subca(self, data):
        if data["type"] == "subca":
            if not data.get("parent"):
                raise ValidationError(
                    "If generating a subca, parent 'authority' must be specified."
                )

    @pre_load
    def ensure_dates(self, data):
        return missing.convert_validity_years(data)


class AuthorityUpdateSchema(LemurInputSchema):
    owner = fields.Email(required=True)
    description = fields.String()
    active = fields.Boolean(missing=True)
    roles = fields.Nested(AssociatedRoleSchema(many=True))
    options = fields.String()


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
    max_issuance_days = fields.Integer()
    default_validity_days = fields.Integer()
    authority_certificate = fields.Nested(RootAuthorityCertificateOutputSchema)


class AuthorityNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    description = fields.String()
    name = fields.String()
    owner = fields.Email()
    plugin = fields.Nested(PluginOutputSchema)
    active = fields.Boolean()
    authority_certificate = fields.Nested(RootAuthorityCertificateOutputSchema, only=["not_after", "not_before"])
    is_cab_compliant = fields.Boolean()
    is_cn_optional = fields.Boolean()
    max_issuance_days = fields.Integer()
    default_validity_days = fields.Integer()


authority_update_schema = AuthorityUpdateSchema()
authority_input_schema = AuthorityInputSchema()
authority_output_schema = AuthorityOutputSchema()
authorities_output_schema = AuthorityOutputSchema(many=True)
