"""
.. module: lemur
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
.. moduleauthor:: Curtis Castrapel <ccastrapel@netflix.com>
.. moduleauthor:: Hossein Shafagh <hshafagh@netflix.com>

"""
import socket
import time
import urllib.parse
from flask import g, request

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
from lemur.dns_providers.views import mod as dns_providers_bp

from lemur.__about__ import (
    __author__,
    __copyright__,
    __email__,
    __license__,
    __summary__,
    __title__,
    __uri__,
    __version__,
)


__all__ = [
    "__title__",
    "__summary__",
    "__uri__",
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "__copyright__",
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
    dns_providers_bp,
)


def create_app(config_path=None):
    app = factory.create_app(
        app_name=__name__, blueprints=LEMUR_BLUEPRINTS, config=config_path
    )
    configure_hook(app)
    return app


def configure_hook(app):
    """

    :param app:
    :return:
    """
    from flask import jsonify
    from werkzeug.exceptions import HTTPException

    custom_response_headers = app.config.get("CUSTOM_RESPONSE_HEADERS", {})

    @app.errorhandler(Exception)
    def handle_error(e):
        code = 500
        if isinstance(e, HTTPException):
            code = e.code

        app.logger.exception(e)
        return jsonify(error=str(e)), code

    @app.before_request
    def before_request():
        g.request_start_time = time.time()

    @app.after_request
    def after_request(response):
        def sanitize_path(*, path: str) -> str:
            """
            Sanitizes the given path, if it starts with "/api/1/" and LOG_SANITIZE_REQUEST_HEADERS is enabled.
            It replaces query parameters with '<sanitized_query_parameters>'.

            :param path: The URL path to be sanitized.
            :return: The sanitized URL path.
            """
            # Handle empty paths
            if not path:
                return path

            # Don't mess with paths that aren't part of the API
            if not path.startswith("/api/1/"):
                return path

            # Skip sanitizing the path if we're told to
            if not app.config.get("LOG_SANITIZE_REQUEST_HEADERS", True):
                return path

            parsed_path = urllib.parse.urlparse(path)
            if parsed_path.query:
                return urllib.parse.urlunparse(
                    (
                        parsed_path.scheme,
                        parsed_path.netloc,
                        parsed_path.path,
                        parsed_path.params,
                        "<sanitized_query_parameters>",
                        parsed_path.fragment
                    )
                )
            return path

        # Log request headers
        skip_endpoints = any(
            endpoint in request.full_path for endpoint in app.config.get("LOG_REQUEST_HEADERS_SKIP_ENDPOINT", [])
        )
        if app.config.get("LOG_REQUEST_HEADERS", False) and not skip_endpoints:
            app.logger.info({
                "lemur": socket.gethostname(),
                "ingress-ip": request.remote_addr,
                "request-id": request.headers.get("X-Request-Id"),
                "ip": request.headers.get("X-Real-Ip", request.remote_addr),
                "method": request.method,
                "scheme": request.headers.get("X-Scheme", request.scheme),
                "path": sanitize_path(path=request.full_path),
                "status": response.status_code,
                "user-agent": request.headers.get("User-Agent"),
                "referer": sanitize_path(path=request.headers.get("Referer")),
                "host": request.headers.get("Host")
            })

        # Update custom response headers
        response.headers.update(custom_response_headers)

        # Return early if we don't have the start time
        if not hasattr(g, "request_start_time"):
            return response

        # Get elapsed time in milliseconds
        elapsed = time.time() - g.request_start_time
        elapsed = int(round(1000 * elapsed))

        # Collect request/response tags
        tags = {
            "endpoint": request.endpoint,
            "request_method": request.method.lower(),
            "status_code": response.status_code,
        }

        # Record our response time metric
        metrics.send("response_time", "TIMER", elapsed, metric_tags=tags)
        metrics.send(f"status_code_{response.status_code}", "counter", 1)
        return response
