"""
.. module: lemur.status.views
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import os

from flask import app, current_app, Blueprint, jsonify
from flask.ext.restful import Api

from lemur.auth.service import AuthenticatedResource


mod = Blueprint('status', __name__)
api = Api(mod)


class Status(AuthenticatedResource):
    """ Defines the 'accounts' endpoint """
    def __init__(self):
        super(Status, self).__init__()

    def get(self):
        if not os.path.isdir(os.path.join(app.config.get("KEY_PATH"), "decrypted")):
            return jsonify({
                'environment': app.config.get('ENVIRONMENT'),
                'status': 'degraded',
                'message': "This Lemur instance is in a degraded state and is unable to issue certificates, please alert {0}".format(
                    current_app.config.get('LEMUR_SECURITY_TEAM_EMAIL')
                )})
        else:
            return jsonify({
                'environment': app.config.get('ENVIRONMENT'),
                'status': 'healthy',
                'message': "This Lemur instance is healthy"})
