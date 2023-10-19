"""
.. module: lemur.plugins.lemur_atlas.plugin
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import json
from typing import Any, Dict

import requests
from requests.exceptions import ConnectionError
from datetime import datetime

from flask import current_app
from lemur.plugins import lemur_atlas as atlas
from lemur.plugins.bases.metric import MetricPlugin


def millis_since_epoch():
    """
    current time since epoch in milliseconds
    """
    epoch = datetime.utcfromtimestamp(0)
    delta = datetime.now() - epoch
    return int(delta.total_seconds() * 1000.0)


class AtlasMetricPlugin(MetricPlugin):
    title = "Atlas"
    slug = "atlas-metric"
    description = "Adds support for sending key metrics to Atlas"
    version = atlas.VERSION

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur"

    options = [
        {
            "name": "sidecar_host",
            "type": "str",
            "required": False,
            "help_message": "If no host is provided localhost is assumed",
            "default": "localhost",
        },
        {"name": "sidecar_port", "type": "int", "required": False, "default": 8078},
    ]

    metric_data: Dict[str, Any] = {}
    sidecar_host = None
    sidecar_port = None

    def submit(
        self, metric_name, metric_type, metric_value, metric_tags=None, options=None
    ):
        if not options:
            options = self.options

        # TODO marshmallow schema?
        valid_types = ["COUNTER", "GAUGE", "TIMER"]
        if metric_type.upper() not in valid_types:
            raise Exception(
                "Invalid Metric Type for Atlas: '{metric}' choose from: {options}".format(
                    metric=metric_type, options=",".join(valid_types)
                )
            )

        if metric_tags:
            if not isinstance(metric_tags, dict):
                raise Exception(
                    "Invalid Metric Tags for Atlas: Tags must be in dict format"
                )

        if (
            metric_value == "NaN"
            or isinstance(metric_value, int)
            or isinstance(metric_value, float)
        ):
            self.metric_data["value"] = metric_value
        else:
            raise Exception("Invalid Metric Value for Atlas: Metric must be a number")

        self.metric_data["type"] = metric_type.upper()
        self.metric_data["name"] = str(metric_name)
        self.metric_data["tags"] = metric_tags
        self.metric_data["timestamp"] = millis_since_epoch()

        self.sidecar_host = self.get_option("sidecar_host", options)
        self.sidecar_port = self.get_option("sidecar_port", options)

        try:
            res = requests.post(
                "http://{host}:{port}/metrics".format(
                    host=self.sidecar_host, port=self.sidecar_port
                ),
                data=json.dumps([self.metric_data]),
            )

            if res.status_code != 200:
                current_app.logger.warning(
                    f"Failed to publish altas metric. {res.content}"
                )

        except ConnectionError:
            current_app.logger.warning(
                "AtlasMetrics: could not connect to sidecar at {host}:{port}".format(
                    host=self.sidecar_host, port=self.sidecar_port
                )
            )
