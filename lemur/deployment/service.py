from flask import current_app
from lemur.extensions import metrics


def rotate_certificate(endpoint, new_cert):
    """
    Rotates a certificate on a given endpoint.

    :param endpoint:
    :param new_cert:
    :return:
    """
    try:
        endpoint.source.plugin.update_endpoint(endpoint, new_cert)
        endpoint.certificate = new_cert
        metrics.send('rotation_success', 'counter', 1, metric_tags={'endpoint': endpoint.name})
    except Exception as e:
        metrics.send('rotation_failure', 'counter', 1, metric_tags={'endpoint': endpoint.name})
        current_app.logger.exception(e)
