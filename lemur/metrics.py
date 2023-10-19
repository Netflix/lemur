"""
.. module: lemur.metrics
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from typing import List

from flask import current_app
from lemur.plugins.base import plugins


class Metrics:
    """
    :param app: The Flask application object. Defaults to None.
    """

    _providers: List[str] = []

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initializes the application with the extension.

        :param app: The Flask application object.
        """
        self._providers = app.config.get("METRIC_PROVIDERS", [])

    def send(self, metric_name, metric_type, metric_value, *args, **kwargs):
        for provider in self._providers:
            current_app.logger.debug(
                "Sending metric '{metric}' to the {provider} provider.".format(
                    metric=metric_name, provider=provider
                )
            )
            p = plugins.get(provider)
            p.submit(metric_name, metric_type, metric_value, *args, **kwargs)
