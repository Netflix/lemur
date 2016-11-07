"""
.. module: lemur.common.schema
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from functools import wraps
from flask import request, current_app

from sqlalchemy.orm.collections import InstrumentedList

from inflection import camelize, underscore
from marshmallow import Schema, post_dump, pre_load, pre_dump


class LemurSchema(Schema):
    """
    Base schema from which all grouper schema's inherit
    """
    __envelope__ = True

    def under(self, data, many=None):
        items = []
        if many:
            for i in data:
                items.append(
                    {underscore(key): value for key, value in i.items()}
                )
            return items
        return {
            underscore(key): value
            for key, value in data.items()
        }

    def camel(self, data, many=None):
        items = []
        if many:
            for i in data:
                items.append(
                    {camelize(key, uppercase_first_letter=False): value for key, value in i.items()}
                )
            return items
        return {
            camelize(key, uppercase_first_letter=False): value
            for key, value in data.items()
        }

    def wrap_with_envelope(self, data, many):
        if many:
            if 'total' in self.context.keys():
                return dict(total=self.context['total'], items=data)
        return data


class LemurInputSchema(LemurSchema):
    @pre_load(pass_many=True)
    def preprocess(self, data, many):
        return self.under(data, many=many)


class LemurOutputSchema(LemurSchema):
    @pre_load(pass_many=True)
    def preprocess(self, data, many):
        if many:
            data = self.unwrap_envelope(data, many)
        return self.under(data, many=many)

    @pre_dump(pass_many=True)
    def unwrap_envelope(self, data, many):
        if many:
            if data:
                if isinstance(data, InstrumentedList) or isinstance(data, list):
                    self.context['total'] = len(data)
                    return data
                else:
                    self.context['total'] = data['total']
            else:
                self.context['total'] = 0
                data = {'items': []}

            return data['items']

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
    errors = dict(message='Validation Error.')
    if messages.get('_schema'):
        errors['reasons'] = {'Schema': {'rule': messages['_schema']}}
    else:
        errors['reasons'] = format_errors(messages)
    return errors


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

                kwargs['data'] = data

            try:
                resp = f(*args, **kwargs)
            except Exception as e:
                current_app.logger.exception(e)
                return dict(message=str(e)), 500

            if isinstance(resp, tuple):
                return resp[0], resp[1]

            if not resp:
                return dict(message="No data found"), 404

            if output_schema:
                data = output_schema.dump(resp)
                return data.data, 200
            return resp, 200

        return decorated_function
    return decorator
