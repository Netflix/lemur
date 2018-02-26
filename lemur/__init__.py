"""
.. module: lemur
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>


"""
from __future__ import absolute_import, division, print_function

from lemur import factory
from lemur.extensions import metrics

from lemur.users.views import mod as users_bp
from lemur.roles.views import mod as roles_bp
from lemur.auth.views import mod as auth_bp
from lemur.domains.views import mod as domains_bp
from lemur.destinations.views import mod as destinations_bp
from lemur.authorities.views import mod as authorities_bp
from lemur.certificates.views import mod as certificates_bp
from lemur.defaults.views import mod as defaults_bp
from lemur.plugins.views import mod as plugins_bp
from lemur.notifications.views import mod as notifications_bp
from lemur.sources.views import mod as sources_bp
from lemur.endpoints.views import mod as endpoints_bp
from lemur.logs.views import mod as logs_bp
from lemur.api_keys.views import mod as api_key_bp
from lemur.pending_certificates.views import mod as pending_certificates_bp

from lemur.__about__ import (
    __author__, __copyright__, __email__, __license__, __summary__, __title__,
    __uri__, __version__
)


__all__ = [
    "__title__", "__summary__", "__uri__", "__version__", "__author__",
    "__email__", "__license__", "__copyright__",
]

LEMUR_BLUEPRINTS = (
    users_bp,
    roles_bp,
    auth_bp,
    domains_bp,
    destinations_bp,
    authorities_bp,
    certificates_bp,
    defaults_bp,
    plugins_bp,
    notifications_bp,
    sources_bp,
    endpoints_bp,
    logs_bp,
    api_key_bp,
    pending_certificates_bp,
)


def create_app(config=None):
    app = factory.create_app(app_name=__name__, blueprints=LEMUR_BLUEPRINTS, config=config)
    configure_hook(app)
    return app


def configure_hook(app):
    """

    :param app:
    :return:
    """
    from flask import jsonify
    from werkzeug.exceptions import HTTPException
    from lemur.decorators import crossdomain
    if app.config.get('CORS'):
        @app.after_request
        @crossdomain(origin=u"http://localhost:3000", methods=['PUT', 'HEAD', 'GET', 'POST', 'OPTIONS', 'DELETE'])
        def after(response):
            return response

    @app.after_request
    def log_status(response):
        metrics.send('status_code_{}'.format(response.status_code), 'counter', 1)
        return response

    @app.errorhandler(Exception)
    def handle_error(e):
        code = 500
        if isinstance(e, HTTPException):
            code = e.code

        app.logger.exception(e)
        return jsonify(error=str(e)), code
