import lemur_statsd as plug
from datadog import DogStatsd
from flask import current_app
from lemur.plugins.bases.metric import MetricPlugin


class StatsdMetricPlugin(MetricPlugin):
    title = "Statsd"
    slug = "statsd-metrics"
    description = "Adds support for sending metrics to Statsd"
    version = plug.VERSION

    def __init__(self):
        host = current_app.config.get("STATSD_HOST")
        port = current_app.config.get("STATSD_PORT")
        prefix = current_app.config.get("STATSD_PREFIX")

        self.statsd = DogStatsd(host=host, port=port, namespace=prefix)

    def submit(
        self, metric_name, metric_type, metric_value, metric_tags=None, options=None
    ):
        valid_types = ["COUNTER", "GAUGE", "TIMER"]
        tags = []

        if metric_type.upper() not in valid_types:
            raise Exception(
                "Invalid Metric Type for Statsd, '{metric}' choose from: {options}".format(
                    metric=metric_type, options=",".join(valid_types)
                )
            )

        if metric_tags:
            if not isinstance(metric_tags, dict):
                raise Exception(
                    "Invalid Metric Tags for Statsd: Tags must be in dict format"
                )
            else:
                tags = list(map(lambda e: "{}:{}".format(*e), metric_tags.items()))

        if metric_type.upper() == "COUNTER":
            self.statsd.increment(metric_name, metric_value, tags)
        elif metric_type.upper() == "GAUGE":
            self.statsd.gauge(metric_name, metric_value, tags)
        elif metric_type.upper() == "TIMER":
            self.statsd.timing(metric_name, metric_value, tags)

        return
