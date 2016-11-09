import arrow
import warnings
from datetime import datetime as dt
from marshmallow.fields import Field
from marshmallow import utils


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
        'iso': utils.isoformat,
        'iso8601': utils.isoformat,
        'rfc': utils.rfcformat,
        'rfc822': utils.rfcformat,
    }

    DATEFORMAT_DESERIALIZATION_FUNCS = {
        'iso': utils.from_iso,
        'iso8601': utils.from_iso,
        'rfc': utils.from_rfc,
        'rfc822': utils.from_rfc,
    }

    DEFAULT_FORMAT = 'iso'

    localtime = False
    default_error_messages = {
        'invalid': 'Not a valid datetime.',
        'format': '"{input}" cannot be formatted as a datetime.',
    }

    def __init__(self, format=None, **kwargs):
        super(ArrowDateTime, self).__init__(**kwargs)
        # Allow this to be None. It may be set later in the ``_serialize``
        # or ``_desrialize`` methods This allows a Schema to dynamically set the
        # dateformat, e.g. from a Meta option
        self.dateformat = format

    def _add_to_schema(self, field_name, schema):
        super(ArrowDateTime, self)._add_to_schema(field_name, schema)
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
                self.fail('format', input=value)
        else:
            return value.strftime(self.dateformat)

    def _deserialize(self, value, attr, data):
        if not value:  # Falsy values, e.g. '', None, [] are not valid
            raise self.fail('invalid')
        self.dateformat = self.dateformat or self.DEFAULT_FORMAT
        func = self.DATEFORMAT_DESERIALIZATION_FUNCS.get(self.dateformat)
        if func:
            try:
                return arrow.get(func(value))
            except (TypeError, AttributeError, ValueError):
                raise self.fail('invalid')
        elif self.dateformat:
            try:
                return dt.datetime.strptime(value, self.dateformat)
            except (TypeError, AttributeError, ValueError):
                raise self.fail('invalid')
        elif utils.dateutil_available:
            try:
                return arrow.get(utils.from_datestring(value))
            except TypeError:
                raise self.fail('invalid')
        else:
            warnings.warn('It is recommended that you install python-dateutil '
                          'for improved datetime deserialization.')
            raise self.fail('invalid')
