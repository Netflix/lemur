"""
.. module: lemur
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>


"""
from flask import jsonify

from lemur import factory

from lemur.users.views import mod as users
from lemur.roles.views import mod as roles
from lemur.auth.views import mod as auth
from lemur.domains.views import mod as domains
from lemur.elbs.views import mod as elbs
from lemur.accounts.views import mod as accounts
from lemur.authorities.views import mod as authorities
from lemur.listeners.views import  mod as listeners
from lemur.certificates.views import mod as certificates
from lemur.status.views import mod as status

LEMUR_BLUEPRINTS = (
    users,
    roles,
    auth,
    domains,
    elbs,
    accounts,
    authorities,
    listeners,
    certificates,
    status
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
    from flask.ext.principal import PermissionDenied
    from lemur.decorators import crossdomain
    if app.config.get('CORS'):
        @app.after_request
        @crossdomain(origin="http://localhost:3000", methods=['PUT', 'HEAD', 'GET', 'POST', 'OPTIONS', 'DELETE'])
        def after(response):
            return response

    @app.errorhandler(PermissionDenied)
    def handle_invalid_usage(error):
        response = {'message': 'You are not allow to access this resource'}
        response.status_code = 403
        return response






