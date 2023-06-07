"""
.. module: lemur.plugins.lemur_atlas_redis.plugin
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Jay Zarfoss
"""
from typing import Dict, Any

from redis import Redis
import json
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


class AtlasMetricRedisPlugin(MetricPlugin):
    title = "AtlasRedis"
    slug = "atlas-metric-redis"
    description = "Adds support for sending key metrics to Atlas via local Redis"
    version = atlas.VERSION

    author = "Jay Zarfoss"
    author_url = "https://github.com/netflix/lemur"

    options = [
        {
            "name": "redis_host",
            "type": "str",
            "required": False,
            "help_message": "If no host is provided localhost is assumed",
            "default": "localhost",
        },
        {"name": "redis_port", "type": "int", "required": False, "default": 28527},
    ]

    metric_data: Dict[str, Any] = {}
    redis_host = None
    redis_port = None

    def submit(
        self, metric_name, metric_type, metric_value, metric_tags=None, options=None
    ):
        if not options:
            options = self.options

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

        self.metric_data["timestamp"] = millis_since_epoch()
        self.metric_data["type"] = metric_type.upper()
        self.metric_data["name"] = str(metric_name)
        self.metric_data["tags"] = metric_tags

        if (
            metric_value == "NaN"
            or isinstance(metric_value, int)
            or isinstance(metric_value, float)
        ):
            self.metric_data["value"] = metric_value
        else:
            raise Exception("Invalid Metric Value for Atlas: Metric must be a number")

        self.redis_host = self.get_option("redis_host", options)
        self.redis_port = self.get_option("redis_port", options)

        try:
            r = Redis(host=self.redis_host, port=self.redis_port, socket_timeout=0.1)
            r.rpush('atlas-agent', json.dumps(self.metric_data))
        except Exception as e:
            current_app.logger.warning(
                "AtlasMetricsRedis: exception [{exception}] could not post atlas metrics to AtlasRedis [{host}:{port}], metric [{metricdata}]".format(
                    exception=e, host=self.redis_host, port=self.redis_port, metricdata=json.dumps(self.metric_data)
                )
            )
