"""
.. module: lemur.common.fields
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import ipaddress
import warnings
from datetime import datetime as dt

import arrow
from cryptography import x509
from flask import current_app
from marshmallow import utils
from marshmallow.exceptions import ValidationError
from marshmallow.fields import Field

from lemur.common import validators


class Hex(Field):
    """
    A hex formatted string.
    """

    def _serialize(self, value, attr, obj):
        if value:
            value = hex(int(value))[2:].upper()
        return value


class ArrowDateTime(Field):
    """A formatted datetime string in UTC.

    Example: ``'2014-12-22T03:12:58.019077+00:00'``

    Timezone-naive `datetime` objects are converted to
    UTC (+00:00) by :meth:`Schema.dump <marshmallow.Schema.dump>`.
    :meth:`Schema.load <marshmallow.Schema.load>` returns `datetime`
    objects that are timezone-aware.

    :param str format: Either ``"rfc"`` (for RFC822), ``"iso"`` (for ISO8601),
        or a date format string. If `None`, defaults to "iso".
    :param kwargs: The same keyword arguments that :class:`Field` receives.

    """

    DATEFORMAT_SERIALIZATION_FUNCS = {
        "iso": utils.isoformat,
        "iso8601": utils.isoformat,
        "rfc": utils.rfcformat,
        "rfc822": utils.rfcformat,
    }

    DATEFORMAT_DESERIALIZATION_FUNCS = {
        "iso": utils.from_iso,
        "iso8601": utils.from_iso,
        "rfc": utils.from_rfc,
        "rfc822": utils.from_rfc,
    }

    DEFAULT_FORMAT = "iso"

    localtime = False
    default_error_messages = {
        "invalid": "Not a valid datetime.",
        "format": '"{input}" cannot be formatted as a datetime.',
    }

    def __init__(self, format=None, **kwargs):
        super().__init__(**kwargs)
        # Allow this to be None. It may be set later in the ``_serialize``
        # or ``_desrialize`` methods This allows a Schema to dynamically set the
        # dateformat, e.g. from a Meta option
        self.dateformat = format

    def _add_to_schema(self, field_name, schema):
        super()._add_to_schema(field_name, schema)
        self.dateformat = self.dateformat or schema.opts.dateformat

    def _serialize(self, value, attr, obj):
        if value is None:
            return None
        self.dateformat = self.dateformat or self.DEFAULT_FORMAT
        format_func = self.DATEFORMAT_SERIALIZATION_FUNCS.get(self.dateformat, None)
        if format_func:
            try:
                return format_func(value, localtime=self.localtime)
            except (AttributeError, ValueError) as err:
                self.fail("format", input=value)
        else:
            return value.strftime(self.dateformat)

    def _deserialize(self, value, attr, data):
        if not value:  # Falsy values, e.g. '', None, [] are not valid
            raise self.fail("invalid")
        self.dateformat = self.dateformat or self.DEFAULT_FORMAT
        func = self.DATEFORMAT_DESERIALIZATION_FUNCS.get(self.dateformat)
        if func:
            try:
                return arrow.get(func(value))
            except (TypeError, AttributeError, ValueError):
                raise self.fail("invalid")
        elif self.dateformat:
            try:
                return dt.datetime.strptime(value, self.dateformat)
            except (TypeError, AttributeError, ValueError):
                raise self.fail("invalid")
        elif utils.dateutil_available:
            try:
                return arrow.get(utils.from_datestring(value))
            except TypeError:
                raise self.fail("invalid")
        else:
            warnings.warn(
                "It is recommended that you install python-dateutil "
                "for improved datetime deserialization."
            )
            raise self.fail("invalid")


class KeyUsageExtension(Field):
    """An x509.KeyUsage ExtensionType object

    Dict of KeyUsage names/values are deserialized into an x509.KeyUsage object
    and back.

    :param kwargs: The same keyword arguments that :class:`Field` receives.

    """

    def _serialize(self, value, attr, obj):
        return {
            "useDigitalSignature": value.digital_signature,
            "useNonRepudiation": value.content_commitment,
            "useKeyEncipherment": value.key_encipherment,
            "useDataEncipherment": value.data_encipherment,
            "useKeyAgreement": value.key_agreement,
            "useKeyCertSign": value.key_cert_sign,
            "useCRLSign": value.crl_sign,
            "useEncipherOnly": value._encipher_only,
            "useDecipherOnly": value._decipher_only,
        }

    def _deserialize(self, value, attr, data):
        keyusages = {
            "digital_signature": False,
            "content_commitment": False,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        }

        for k, v in value.items():
            if k == "useDigitalSignature":
                keyusages["digital_signature"] = v

            elif k == "useNonRepudiation":
                keyusages["content_commitment"] = v

            elif k == "useKeyEncipherment":
                keyusages["key_encipherment"] = v

            elif k == "useDataEncipherment":
                keyusages["data_encipherment"] = v

            elif k == "useKeyCertSign":
                keyusages["key_cert_sign"] = v

            elif k == "useCRLSign":
                keyusages["crl_sign"] = v

            elif k == "useKeyAgreement":
                keyusages["key_agreement"] = v

            elif k == "useEncipherOnly" and v:
                keyusages["encipher_only"] = True
                keyusages["key_agreement"] = True

            elif k == "useDecipherOnly" and v:
                keyusages["decipher_only"] = True
                keyusages["key_agreement"] = True

        if keyusages["encipher_only"] and keyusages["decipher_only"]:
            raise ValidationError(
                "A certificate cannot have both Encipher Only and Decipher Only Extended Key Usages."
            )

        return x509.KeyUsage(
            digital_signature=keyusages["digital_signature"],
            content_commitment=keyusages["content_commitment"],
            key_encipherment=keyusages["key_encipherment"],
            data_encipherment=keyusages["data_encipherment"],
            key_agreement=keyusages["key_agreement"],
            key_cert_sign=keyusages["key_cert_sign"],
            crl_sign=keyusages["crl_sign"],
            encipher_only=keyusages["encipher_only"],
            decipher_only=keyusages["decipher_only"],
        )


class ExtendedKeyUsageExtension(Field):
    """An x509.ExtendedKeyUsage ExtensionType object

    Dict of ExtendedKeyUsage names/values are deserialized into an x509.ExtendedKeyUsage object
    and back.

    :param kwargs: The same keyword arguments that :class:`Field` receives.

    """

    def _serialize(self, value, attr, obj):
        usages = value._usages
        usage_list = {}
        for usage in usages:
            if usage == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                usage_list["useClientAuthentication"] = True

            elif usage == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                usage_list["useServerAuthentication"] = True

            elif usage == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                usage_list["useCodeSigning"] = True

            elif usage == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                usage_list["useEmailProtection"] = True

            elif usage == x509.oid.ExtendedKeyUsageOID.TIME_STAMPING:
                usage_list["useTimestamping"] = True

            elif usage == x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING:
                usage_list["useOCSPSigning"] = True

            elif usage.dotted_string == "1.3.6.1.5.5.7.3.14":
                usage_list["useEapOverLAN"] = True

            elif usage.dotted_string == "1.3.6.1.5.5.7.3.13":
                usage_list["useEapOverPPP"] = True

            elif usage.dotted_string == "1.3.6.1.4.1.311.20.2.2":
                usage_list["useSmartCardLogon"] = True

            else:
                current_app.logger.warning(
                    "Unable to serialize ExtendedKeyUsage with OID: {usage}".format(
                        usage=usage.dotted_string
                    )
                )

        return usage_list

    def _deserialize(self, value, attr, data):
        usage_oids = []
        for k, v in value.items():
            if k == "useClientAuthentication" and v:
                usage_oids.append(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)

            elif k == "useServerAuthentication" and v:
                usage_oids.append(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)

            elif k == "useCodeSigning" and v:
                usage_oids.append(x509.oid.ExtendedKeyUsageOID.CODE_SIGNING)

            elif k == "useEmailProtection" and v:
                usage_oids.append(x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION)

            elif k == "useTimestamping" and v:
                usage_oids.append(x509.oid.ExtendedKeyUsageOID.TIME_STAMPING)

            elif k == "useOCSPSigning" and v:
                usage_oids.append(x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING)

            elif k == "useEapOverLAN" and v:
                usage_oids.append(x509.oid.ObjectIdentifier("1.3.6.1.5.5.7.3.14"))

            elif k == "useEapOverPPP" and v:
                usage_oids.append(x509.oid.ObjectIdentifier("1.3.6.1.5.5.7.3.13"))

            elif k == "useSmartCardLogon" and v:
                usage_oids.append(x509.oid.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"))

            else:
                current_app.logger.warning(
                    "Unable to deserialize ExtendedKeyUsage with name: {key}".format(
                        key=k
                    )
                )

        return x509.ExtendedKeyUsage(usage_oids)


class BasicConstraintsExtension(Field):
    """An x509.BasicConstraints ExtensionType object

    Dict of CA boolean and a path_length integer names/values are deserialized into an x509.BasicConstraints object
    and back.

    :param kwargs: The same keyword arguments that :class:`Field` receives.

    """

    def _serialize(self, value, attr, obj):
        return {"ca": value.ca, "path_length": value.path_length}

    def _deserialize(self, value, attr, data):
        ca = value.get("ca", False)
        path_length = value.get("path_length", None)

        if ca:
            if not isinstance(path_length, (type(None), int)):
                raise ValidationError(
                    "A CA certificate path_length (for BasicConstraints) must be None or an integer."
                )
            return x509.BasicConstraints(ca=True, path_length=path_length)
        else:
            return x509.BasicConstraints(ca=False, path_length=None)


class SubjectAlternativeNameExtension(Field):
    """An x509.SubjectAlternativeName ExtensionType object

    Dict of CA boolean and a path_length integer names/values are deserialized into an x509.BasicConstraints object
    and back.

    :param kwargs: The same keyword arguments that :class:`Field` receives.

    """

    def _serialize(self, value, attr, obj):
        general_names = []
        name_type = None

        if value:
            for name in value._general_names:
                value = name.value

                if isinstance(name, x509.DNSName):
                    name_type = "DNSName"

                elif isinstance(name, x509.IPAddress):
                    if isinstance(value, ipaddress.IPv4Network):
                        name_type = "IPNetwork"
                    else:
                        name_type = "IPAddress"

                    value = str(value)

                elif isinstance(name, x509.UniformResourceIdentifier):
                    name_type = "uniformResourceIdentifier"

                elif isinstance(name, x509.DirectoryName):
                    name_type = "directoryName"

                elif isinstance(name, x509.RFC822Name):
                    name_type = "rfc822Name"

                elif isinstance(name, x509.RegisteredID):
                    name_type = "registeredID"
                    value = value.dotted_string
                else:
                    current_app.logger.warning(
                        f"Unknown SubAltName type: {name}"
                    )
                    continue

                general_names.append({"nameType": name_type, "value": value})

        return general_names

    def _deserialize(self, value, attr, data):
        general_names = []
        for name in value:
            if name["nameType"] == "DNSName":
                validators.sensitive_domain(name["value"])
                general_names.append(x509.DNSName(name["value"]))

            elif name["nameType"] == "IPAddress":
                general_names.append(
                    x509.IPAddress(ipaddress.ip_address(name["value"]))
                )

            elif name["nameType"] == "IPNetwork":
                general_names.append(
                    x509.IPAddress(ipaddress.ip_network(name["value"]))
                )

            elif name["nameType"] == "uniformResourceIdentifier":
                general_names.append(x509.UniformResourceIdentifier(name["value"]))

            elif name["nameType"] == "directoryName":
                # TODO: Need to parse a string in name['value'] like:
                # 'CN=Common Name, O=Org Name, OU=OrgUnit Name, C=US, ST=ST, L=City/emailAddress=person@example.com'
                # or
                # 'CN=Common Name/O=Org Name/OU=OrgUnit Name/C=US/ST=NH/L=City/emailAddress=person@example.com'
                # and turn it into something like:
                # x509.Name([
                #     x509.NameAttribute(x509.OID_COMMON_NAME, "Common Name"),
                #     x509.NameAttribute(x509.OID_ORGANIZATION_NAME, "Org Name"),
                #     x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, "OrgUnit Name"),
                #     x509.NameAttribute(x509.OID_COUNTRY_NAME, "US"),
                #     x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, "NH"),
                #     x509.NameAttribute(x509.OID_LOCALITY_NAME, "City"),
                #     x509.NameAttribute(x509.OID_EMAIL_ADDRESS, "person@example.com")
                # ]
                # general_names.append(x509.DirectoryName(x509.Name(BLAH))))
                pass

            elif name["nameType"] == "rfc822Name":
                general_names.append(x509.RFC822Name(name["value"]))

            elif name["nameType"] == "registeredID":
                general_names.append(
                    x509.RegisteredID(x509.ObjectIdentifier(name["value"]))
                )

            elif name["nameType"] == "otherName":
                # This has two inputs (type and value), so it doesn't fit the mold of the rest of these GeneralName entities.
                # general_names.append(x509.OtherName(name['type'], bytes(name['value']), 'utf-8'))
                pass

            elif name["nameType"] == "x400Address":
                # The Python Cryptography library doesn't support x400Address types (yet?)
                pass

            elif name["nameType"] == "EDIPartyName":
                # The Python Cryptography library doesn't support EDIPartyName types (yet?)
                pass

            else:
                current_app.logger.warning(
                    "Unable to deserialize SubAltName with type: {name_type}".format(
                        name_type=name["nameType"]
                    )
                )

        return x509.SubjectAlternativeName(general_names)
