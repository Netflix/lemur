"""
.. module: lemur.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from marshmallow import fields, post_load, pre_load, post_dump
from marshmallow.exceptions import ValidationError
from sqlalchemy.orm.exc import NoResultFound

from lemur.authorities.models import Authority
from lemur.certificates.models import Certificate
from lemur.common import validators
from lemur.common.fields import (
    KeyUsageExtension,
    ExtendedKeyUsageExtension,
    BasicConstraintsExtension,
    SubjectAlternativeNameExtension,
)
from lemur.common.schema import LemurSchema, LemurInputSchema, LemurOutputSchema
from lemur.destinations.models import Destination
from lemur.dns_providers.models import DnsProvider
from lemur.notifications.models import Notification
from lemur.plugins import plugins
from lemur.plugins.utils import get_plugin_option
from lemur.policies.models import RotationPolicy
from lemur.roles.models import Role
from lemur.users.models import User


def validate_options(options):
    """
    Ensures that the plugin options are valid.
    :param options:
    :return:
    """
    interval = get_plugin_option("interval", options)
    unit = get_plugin_option("unit", options)

    if not interval and not unit:
        return

    if unit == "month":
        interval *= 30

    elif unit == "week":
        interval *= 7

    if interval > 90:
        raise ValidationError(
            "Notification cannot be more than 90 days into the future."
        )


def get_object_attribute(data, many=False):
    if many:
        ids = [d.get("id") for d in data]
        names = [d.get("name") for d in data]

        if None in ids:
            if None in names:
                raise ValidationError("Associated object require a name or id.")
            else:
                return "name"
        return "id"
    else:
        if data.get("id"):
            return "id"
        elif data.get("name"):
            return "name"
        else:
            raise ValidationError("Associated object require a name or id.")


def fetch_objects(model, data, many=False):
    attr = get_object_attribute(data, many=many)

    if many:
        values = [v[attr] for v in data]
        items = model.query.filter(getattr(model, attr).in_(values)).all()
        found = [getattr(i, attr) for i in items]
        diff = set(values).symmetric_difference(set(found))

        if diff:
            raise ValidationError(
                "Unable to locate {model} with {attr} {diff}".format(
                    model=model, attr=attr, diff=",".join(list(diff))
                )
            )

        return items

    else:
        try:
            return model.query.filter(getattr(model, attr) == data[attr]).one()
        except NoResultFound:
            raise ValidationError(
                "Unable to find {model} with {attr}: {data}".format(
                    model=model, attr=attr, data=data[attr]
                )
            )


class AssociatedAuthoritySchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        return fetch_objects(Authority, data, many=many)


class AssociatedDnsProviderSchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        return fetch_objects(DnsProvider, data, many=many)


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


class AssociatedRotationPolicySchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        return fetch_objects(RotationPolicy, data, many=many)


class PluginInputSchema(LemurInputSchema):
    plugin_options = fields.List(fields.Dict(), validate=validate_options)
    slug = fields.String(required=True)
    title = fields.String()
    description = fields.String()

    @post_load
    def get_object(self, data, many=False):
        try:
            data["plugin_object"] = plugins.get(data["slug"])
        except KeyError as e:
            raise ValidationError(
                "Unable to find plugin. Slug: {} Reason: {}".format(data["slug"], e)
            )

        plugin_options_validated = []

        # parse any sub-plugins
        for option in data.get("plugin_options", []):
            server_options_user_value = None
            if not option:
                continue  # Angular sometimes generates empty option objects.
            try:
                option_name = option["name"]
                option_value = option.get("value", "")
            except KeyError as e:
                raise ValidationError(
                    f"Unable to get plugin options. Slug: {data['slug']} Option: {option!r}"
                )
            if "plugin" in option.get("type", []):
                # for plugins, sub-plugin options are validated in a recursive call to schema.load() below
                sub_data, errors = PluginInputSchema().load(option_value)
                if errors:
                    raise ValidationError(
                        f"Unable to load plugin options. Slug: {data['slug']} Option {option_name}"
                    )
                option["value"] = sub_data
                plugin_options_validated.append(option)
            elif data["plugin_object"]:
                # validate user inputs for sub-plugin options and only accept "value" field from user
                try:
                    # Run regex validation rule on user input
                    data["plugin_object"].validate_option_value(option_name, option_value)

                    # Only accept the "value" field from the user - keep server default options for all other fields
                    server_options_with_user_value = data["plugin_object"].get_server_options(option_name)
                    if server_options_with_user_value is None:  # no server options discovered
                        plugin_options_validated.append(option)
                        continue
                    server_options_with_user_value["value"] = option_value
                    plugin_options_validated.append(server_options_with_user_value)

                except (ValueError, ValidationError) as e:
                    raise ValidationError(
                        f"Unable to validate plugin options. Slug: {data['slug']} Option {option_name}: {e}"
                    )

        data["plugin_options"] = plugin_options_validated
        return data


class PluginOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    label = fields.String()
    description = fields.String()
    active = fields.Boolean()
    options = fields.List(fields.Dict(), dump_to="pluginOptions")
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
        return {"includeAIA": data["include_aia"]}


class CRLDistributionPointsSchema(BaseExtensionSchema):
    include_crl_dp = fields.String()

    @post_dump
    def handle_keys(self, data):
        return {"includeCRLDP": data["include_crl_dp"]}


class SubjectKeyIdentifierSchema(BaseExtensionSchema):
    include_ski = fields.Boolean()

    @post_dump
    def handle_keys(self, data):
        return {"includeSKI": data["include_ski"]}


class CustomOIDSchema(BaseExtensionSchema):
    oid = fields.String()
    encoding = fields.String(validate=validators.encoding)
    value = fields.String()
    is_critical = fields.Boolean()


class NamesSchema(BaseExtensionSchema):
    names = SubjectAlternativeNameExtension()


class ExtensionSchema(BaseExtensionSchema):
    basic_constraints = (
        BasicConstraintsExtension()
    )  # some devices balk on default basic constraints
    key_usage = KeyUsageExtension()
    extended_key_usage = ExtendedKeyUsageExtension()
    subject_key_identifier = fields.Nested(SubjectKeyIdentifierSchema)
    sub_alt_names = fields.Nested(NamesSchema, missing={"names": []})
    authority_key_identifier = fields.Nested(AuthorityKeyIdentifierSchema)
    certificate_info_access = fields.Nested(CertificateInfoAccessSchema)
    crl_distribution_points = fields.Nested(
        CRLDistributionPointsSchema, dump_to="cRL_distribution_points"
    )
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
