"""
.. module: lemur.certificates.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from flask_restful import inputs
from flask_restful.reqparse import RequestParser
from marshmallow import fields, validate, validates_schema, post_load, pre_load, post_dump
from marshmallow.exceptions import ValidationError

from lemur.authorities.schemas import AuthorityNestedOutputSchema
from lemur.certificates import utils as cert_utils
from lemur.common import missing, utils, validators
from lemur.common.fields import ArrowDateTime, Hex
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.constants import CERTIFICATE_KEY_TYPES, CRLReason
from lemur.destinations.schemas import DestinationNestedOutputSchema
from lemur.dns_providers.schemas import DnsProvidersNestedOutputSchema
from lemur.domains.schemas import DomainNestedOutputSchema
from lemur.notifications import service as notification_service
from lemur.notifications.schemas import NotificationNestedOutputSchema
from lemur.policies.schemas import RotationPolicyNestedOutputSchema
from lemur.roles import service as roles_service
from lemur.roles.schemas import RoleNestedOutputSchema
from lemur.schemas import (
    AssociatedAuthoritySchema,
    AssociatedDestinationSchema,
    AssociatedCertificateSchema,
    AssociatedNotificationSchema,
    AssociatedDnsProviderSchema,
    PluginInputSchema,
    ExtensionSchema,
    AssociatedRoleSchema,
    EndpointNestedOutputSchema,
    AssociatedRotationPolicySchema,
)
from lemur.users.schemas import UserNestedOutputSchema


class CertificateSchema(LemurInputSchema):
    owner = fields.Email(required=True)
    description = fields.String(missing="", allow_none=True)


class CertificateCreationSchema(CertificateSchema):
    @post_load
    def default_notification(self, data):
        if not data["notifications"]:
            data[
                "notifications"
            ] += notification_service.create_default_expiration_notifications(
                "DEFAULT_{}".format(data["owner"].split("@")[0].upper()),
                [data["owner"]],
            )

            data[
                "notifications"
            ] += notification_service.create_default_expiration_notifications(
                "DEFAULT_SECURITY",
                current_app.config.get("LEMUR_SECURITY_TEAM_EMAIL"),
                current_app.config.get("LEMUR_SECURITY_TEAM_EMAIL_INTERVALS", None),
            )
        return data


class CertificateInputSchema(CertificateCreationSchema):
    name = fields.String()
    # Earlier common_name was a required field and thus in most places there is no None check for it. Adding missing=""
    # as it is not a required field anymore.
    common_name = fields.String(validate=validators.common_name, missing="")
    authority = fields.Nested(AssociatedAuthoritySchema, required=True)

    validity_start = ArrowDateTime(allow_none=True)
    validity_end = ArrowDateTime(allow_none=True)
    validity_years = fields.Integer(allow_none=True)

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replaces = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    replacements = fields.Nested(
        AssociatedCertificateSchema, missing=[], many=True
    )  # deprecated
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)
    dns_provider = fields.Nested(
        AssociatedDnsProviderSchema, missing=None, allow_none=True, required=False
    )

    csr = fields.String(allow_none=True, validate=validators.csr)

    key_type = fields.String(
        validate=validate.OneOf(CERTIFICATE_KEY_TYPES), missing="ECCPRIME256V1"
    )

    notify = fields.Boolean(default=True)
    rotation = fields.Boolean()
    rotation_policy = fields.Nested(
        AssociatedRotationPolicySchema,
        missing={"name": "default"},
        allow_none=True,
        default={"name": "default"},
    )

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

    extensions = fields.Nested(ExtensionSchema, missing={})

    @validates_schema
    def validate_authority(self, data):
        if 'authority' not in data:
            raise ValidationError("Missing Authority.")

        if isinstance(data["authority"], str):
            raise ValidationError("Authority not found.")

        if not data["authority"].active:
            raise ValidationError("The authority is inactive.", ["authority"])

    @validates_schema
    def validate_dates(self, data):
        validators.dates(data)

    @post_load
    def validate_common_name(self, data):
        if data["authority"] and (not data["authority"].is_cn_optional) and data["common_name"] == "":
            raise ValidationError("Missing common_name")

        if len(data["extensions"]["sub_alt_names"]["names"]) == 0 and data["common_name"] == "":
            raise ValidationError("Missing common_name, either CN or SAN must be present")

    @pre_load
    def load_data(self, data):
        if data.get("replacements"):
            data["replaces"] = data[
                "replacements"
            ]  # TODO remove when field is deprecated
        if data.get("csr"):
            csr_sans = cert_utils.get_sans_from_csr(data["csr"])
            if not data.get("extensions"):
                data["extensions"] = {"subAltNames": {"names": []}}
            elif not data["extensions"].get("subAltNames"):
                data["extensions"]["subAltNames"] = {"names": []}
            elif not data["extensions"]["subAltNames"].get("names"):
                data["extensions"]["subAltNames"]["names"] = []

            data["extensions"]["subAltNames"]["names"] = csr_sans

            common_name = cert_utils.get_cn_from_csr(data["csr"])
            if common_name:
                data["common_name"] = common_name
            key_type = cert_utils.get_key_type_from_csr(data["csr"])
            if key_type:
                data["key_type"] = key_type

        # This code will be exercised for certificate import (without CSR)
        if data.get("key_type") is None:
            if data.get("body"):
                data["key_type"] = utils.get_key_type_from_certificate(data["body"])
            else:
                data["key_type"] = "ECCPRIME256V1"  # default value

        return missing.convert_validity_years(data)


class CertificateEditInputSchema(CertificateSchema):
    owner = fields.String()

    notify = fields.Boolean()
    rotation = fields.Boolean()

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replaces = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    replacements = fields.Nested(
        AssociatedCertificateSchema, missing=[], many=True
    )  # deprecated
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)

    @pre_load
    def load_data(self, data):
        if data.get("replacements"):
            data["replaces"] = data[
                "replacements"
            ]  # TODO remove when field is deprecated

        if data.get("owner"):
            # Check if role already exists. This avoids adding duplicate role.
            if data.get("roles") and any(r.get("name") == data["owner"] for r in data["roles"]):
                return data

            # Add required role
            owner_role = roles_service.get_or_create(
                data["owner"],
                description=f"Auto generated role based on owner: {data['owner']}"
            )

            # Put  role info in correct format using RoleNestedOutputSchema
            owner_role_dict = RoleNestedOutputSchema().dump(owner_role).data
            if data.get("roles"):
                data["roles"].append(owner_role_dict)
            else:
                data["roles"] = [owner_role_dict]

        return data

    @post_load
    def enforce_notifications(self, data):
        """
        Add default notification for current owner if none exist.
        This ensures that the default notifications are added in the event of owner change.
        Old owner notifications are retained unless explicitly removed later in the code path.
        :param data:
        :return:
        """
        if data.get("owner"):
            notification_name = "DEFAULT_{}".format(
                data["owner"].split("@")[0].upper()
            )

            # Even if one default role exists, return
            # This allows a User to remove unwanted default notification for current owner
            if any(n.label.startswith(notification_name) for n in data["notifications"]):
                return data

            data[
                "notifications"
            ] += notification_service.create_default_expiration_notifications(
                notification_name, [data["owner"]]
            )

        return data


class CertificateNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    name = fields.String()
    owner = fields.Email()
    creator = fields.Nested(UserNestedOutputSchema)
    description = fields.String()

    status = fields.String()

    bits = fields.Integer()
    body = fields.String()
    chain = fields.String()
    csr = fields.String()
    active = fields.Boolean()

    rotation = fields.Boolean()
    notify = fields.Boolean()
    rotation_policy = fields.Nested(RotationPolicyNestedOutputSchema)

    # Note aliasing is the first step in deprecating these fields.
    cn = fields.String()  # deprecated
    common_name = fields.String(attribute="cn")

    not_after = fields.DateTime()  # deprecated
    validity_end = ArrowDateTime(attribute="not_after")

    not_before = fields.DateTime()  # deprecated
    validity_start = ArrowDateTime(attribute="not_before")

    issuer = fields.Nested(AuthorityNestedOutputSchema)


class CertificateCloneSchema(LemurOutputSchema):
    __envelope__ = False
    description = fields.String()
    common_name = fields.String()


class CertificateOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    external_id = fields.String()
    bits = fields.Integer()
    body = fields.String()
    chain = fields.String()
    csr = fields.String()
    deleted = fields.Boolean(default=False)
    description = fields.String()
    issuer = fields.String()
    name = fields.String()
    dns_provider_id = fields.Integer(required=False, allow_none=True)
    date_created = ArrowDateTime()
    resolved = fields.Boolean(required=False, allow_none=True)
    resolved_cert_id = fields.Integer(required=False, allow_none=True)

    rotation = fields.Boolean()

    # Note aliasing is the first step in deprecating these fields.
    notify = fields.Boolean()
    active = fields.Boolean(attribute="notify")
    has_private_key = fields.Boolean()

    cn = fields.String()
    common_name = fields.String(attribute="cn")
    distinguished_name = fields.String()

    not_after = fields.DateTime()
    validity_end = ArrowDateTime(attribute="not_after")

    not_before = fields.DateTime()
    validity_start = ArrowDateTime(attribute="not_before")

    owner = fields.Email()
    san = fields.Boolean()
    serial = fields.String()
    serial_hex = Hex(attribute="serial")
    signing_algorithm = fields.String()
    key_type = fields.String(allow_none=True)

    status = fields.String()
    user = fields.Nested(UserNestedOutputSchema)

    extensions = fields.Nested(ExtensionSchema)

    # associated objects
    domains = fields.Nested(DomainNestedOutputSchema, many=True)
    destinations = fields.Nested(DestinationNestedOutputSchema, many=True)
    notifications = fields.Nested(NotificationNestedOutputSchema, many=True)
    replaces = fields.Nested(CertificateNestedOutputSchema, many=True)
    authority = fields.Nested(AuthorityNestedOutputSchema)
    dns_provider = fields.Nested(DnsProvidersNestedOutputSchema)
    roles = fields.Nested(RoleNestedOutputSchema, many=True)
    endpoints = fields.Nested(EndpointNestedOutputSchema, many=True, missing=[])
    replaced_by = fields.Nested(
        CertificateNestedOutputSchema, many=True, attribute="replaced"
    )
    rotation_policy = fields.Nested(RotationPolicyNestedOutputSchema)

    country = fields.String()
    location = fields.String()
    state = fields.String()
    organization = fields.String()
    organizational_unit = fields.String()

    @post_dump
    def handle_subject_details(self, data):
        subject_details = ["country", "state", "location", "organization", "organizational_unit"]

        # Remove subject details if authority is CA/Browser Forum compliant. The code will use default set of values in that case.
        # If CA/Browser Forum compliance of an authority is unknown (None), it is safe to fallback to default values. Thus below
        # condition checks for 'not False' ==> 'True or None'
        if data.get("authority"):
            is_cab_compliant = data.get("authority").get("isCabCompliant")

            if is_cab_compliant is not False:
                for field in subject_details:
                    data.pop(field, None)

        # Removing subject fields if None, else it complains in de-serialization
        for field in subject_details:
            if field in data and data[field] is None:
                data.pop(field)

        # Earlier common_name was a required field and thus in most places it is checked not be None
        # Now that it is optional, setting value as empty string instead of None for backward compatibility
        if data.get("common_name") is None:
            data["common_name"] = ""


class CertificateShortOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    name = fields.String()
    owner = fields.Email()
    notify = fields.Boolean()
    rotation = fields.Boolean()
    authority = fields.Nested(AuthorityNestedOutputSchema)
    issuer = fields.String()
    cn = fields.String()


class CertificateUploadInputSchema(CertificateCreationSchema):
    name = fields.String()
    authority = fields.Nested(AssociatedAuthoritySchema, required=False)
    notify = fields.Boolean(missing=True)
    external_id = fields.String(missing=None, allow_none=True)
    private_key = fields.String()
    body = fields.String(required=True)
    chain = fields.String(missing=None, allow_none=True)
    csr = fields.String(required=False, allow_none=True, validate=validators.csr)
    key_type = fields.String()

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replaces = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)

    @validates_schema
    def keys(self, data):
        if data.get("destinations"):
            if not data.get("private_key"):
                raise ValidationError("Destinations require private key.")

    @validates_schema
    def validate_cert_private_key_chain(self, data):
        cert = None
        key = None
        if data.get("body"):
            try:
                cert = utils.parse_certificate(data["body"])
            except ValueError:
                raise ValidationError(
                    "Public certificate presented is not valid.", field_names=["body"]
                )

        if data.get("private_key"):
            try:
                key = utils.parse_private_key(data["private_key"])
            except ValueError:
                raise ValidationError(
                    "Private key presented is not valid.", field_names=["private_key"]
                )

        if cert and key:
            # Throws ValidationError
            validators.verify_private_key_match(key, cert)

        if data.get("chain"):
            try:
                chain = utils.parse_cert_chain(data["chain"])
            except ValueError:
                raise ValidationError(
                    "Invalid certificate in certificate chain.", field_names=["chain"]
                )

            # Throws ValidationError
            validators.verify_cert_chain([cert] + chain)

    @pre_load
    def load_data(self, data):
        if data.get("body"):
            try:
                data["key_type"] = utils.get_key_type_from_certificate(data["body"])
            except ValueError:
                raise ValidationError(
                    "Public certificate presented is not valid.", field_names=["body"]
                )


class CertificateExportInputSchema(LemurInputSchema):
    plugin = fields.Nested(PluginInputSchema)


class CertificateNotificationOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    description = fields.String()
    issuer = fields.String()
    name = fields.String()
    owner = fields.Email()
    user = fields.Nested(UserNestedOutputSchema)
    validity_end = ArrowDateTime(attribute="not_after")
    replaced_by = fields.Nested(
        CertificateNestedOutputSchema, many=True, attribute="replaced"
    )
    replaces = fields.Nested(
        CertificateNestedOutputSchema, many=True, attribute="replaces"
    )
    endpoints = fields.Nested(EndpointNestedOutputSchema, many=True, missing=[])


class CertificateRevokeSchema(LemurInputSchema):
    comments = fields.String()
    crl_reason = fields.String(validate=validate.OneOf(CRLReason.__members__), missing="unspecified")


certificates_list_request_parser = RequestParser()
certificates_list_request_parser.add_argument("short", type=inputs.boolean, default=False, location="args")


def certificates_list_output_schema_factory():
    args = certificates_list_request_parser.parse_args()
    if args["short"]:
        return certificates_short_output_schema
    else:
        return certificates_output_schema


certificate_input_schema = CertificateInputSchema()
certificate_output_schema = CertificateOutputSchema()
certificates_output_schema = CertificateOutputSchema(many=True)
certificates_short_output_schema = CertificateShortOutputSchema(many=True)
certificate_upload_input_schema = CertificateUploadInputSchema()
certificate_export_input_schema = CertificateExportInputSchema()
certificate_edit_input_schema = CertificateEditInputSchema()
certificate_notification_output_schema = CertificateNotificationOutputSchema()
certificate_revoke_schema = CertificateRevokeSchema()
