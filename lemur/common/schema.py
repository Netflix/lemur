"""
.. module: lemur.common.schema
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from functools import wraps

from flask import request, current_app
from inflection import camelize, underscore
from marshmallow import Schema, post_dump, pre_load
from sentry_sdk import capture_exception
from sqlalchemy.orm.collections import InstrumentedList


class LemurSchema(Schema):
    """
    Base schema from which all grouper schema's inherit
    """

    __envelope__ = True

    def under(self, data, many=None):
        items = []
        if many:
            for i in data:
                items.append({underscore(key): value for key, value in i.items()})
            return items
        return {underscore(key): value for key, value in data.items()}

    def camel(self, data, many=None):
        items = []
        if many:
            for i in data:
                items.append(
                    {
                        camelize(key, uppercase_first_letter=False): value
                        for key, value in i.items()
                    }
                )
            return items
        return {
            camelize(key, uppercase_first_letter=False): value
            for key, value in data.items()
        }

    def wrap_with_envelope(self, data, many):
        if many:
            if "total" in self.context.keys():
                return dict(total=self.context["total"], items=data)
        return data


class LemurInputSchema(LemurSchema):
    @pre_load(pass_many=True)
    def preprocess(self, data, many):
        if isinstance(data, dict) and data.get("owner"):
            data["owner"] = data["owner"].lower()
        return self.under(data, many=many)


class LemurOutputSchema(LemurSchema):
    @pre_load(pass_many=True)
    def preprocess(self, data, many):
        if many:
            data = self.unwrap_envelope(data, many)
        return self.under(data, many=many)

    def unwrap_envelope(self, data, many):
        if many:
            if data["items"]:
                if isinstance(data, InstrumentedList) or isinstance(data, list):
                    self.context["total"] = len(data)
                    return data
                else:
                    self.context["total"] = data["total"]
            else:
                self.context["total"] = 0
                data = {"items": []}

            return data["items"]

        return data

    @post_dump(pass_many=True)
    def post_process(self, data, many):
        if data:
            data = self.camel(data, many=many)
        if self.__envelope__:
            return self.wrap_with_envelope(data, many=many)
        else:
            return data


def format_errors(messages):
    errors = {}
    for k, v in messages.items():
        key = camelize(k, uppercase_first_letter=False)
        if isinstance(v, dict):
            errors[key] = format_errors(v)
        elif isinstance(v, list):
            errors[key] = v[0]
    return errors


def wrap_errors(messages):
    errors = dict(message="Validation Error.")
    if messages.get("_schema"):
        errors["reasons"] = {"Schema": {"rule": messages["_schema"]}}
    else:
        errors["reasons"] = format_errors(messages)
    return errors


def unwrap_pagination(data, output_schema):
    if not output_schema:
        return data

    if isinstance(data, dict):
        if "total" in data.keys():
            if data.get("total") == 0:
                return data

            marshaled_data = {"total": data["total"]}
            marshaled_data["items"] = output_schema.dump(data["items"], many=True).data
            return marshaled_data

        return output_schema.dump(data).data

    elif isinstance(data, list):
        marshaled_data = {"total": len(data)}
        marshaled_data["items"] = output_schema.dump(data, many=True).data
        return marshaled_data
    return output_schema.dump(data).data


def validate_schema(input_schema, output_schema):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if input_schema:
                if request.get_json():
                    request_data = request.get_json()
                else:
                    request_data = request.args

                data, errors = input_schema.load(request_data)

                if errors:
                    return wrap_errors(errors), 400

                kwargs["data"] = data

            try:
                resp = f(*args, **kwargs)
            except KeyError as e:
                capture_exception()
                current_app.logger.exception(e)
                missing_field = str(e).replace("'", "")  # This removes quotes around the missing key
                msg = f"`{missing_field}` is required but is missing or not configured.  Please provide and try again."
                return dict(message=msg), 500
            except Exception as e:
                capture_exception()
                current_app.logger.exception(e)
                return dict(message=str(e)), 500

            if isinstance(resp, tuple):
                return resp[0], resp[1]

            if not resp:
                return dict(message="No data found"), 404

            if callable(output_schema):
                output_schema_to_use = output_schema()
            else:
                output_schema_to_use = output_schema

            return unwrap_pagination(resp, output_schema_to_use), 200

        return decorated_function

    return decorator
