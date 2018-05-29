"""
.. module: lemur.policies.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields

from lemur.common.schema import LemurOutputSchema


class RotationPolicyOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    days = fields.Integer()


class RotationPolicyNestedOutputSchema(RotationPolicyOutputSchema):
    pass
