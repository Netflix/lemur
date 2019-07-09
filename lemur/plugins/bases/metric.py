"""
.. module: lemur.plugins.bases.metric
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.base import Plugin


class MetricPlugin(Plugin):
    type = "metric"

    def submit(
        self, metric_name, metric_type, metric_value, metric_tags=None, options=None
    ):
        raise NotImplementedError
