from flask import current_app

import lemur.deployment
from lemur.extensions import metrics
from lemur.certificates.service import reissue_certificate


def rotate_certificate(endpoint, new_cert):
    """Rotates a certificate on a given endpoint."""
    try:
        endpoint.source.plugin.update_endpoint(endpoint, new_cert)
        endpoint.certificate = new_cert
    except Exception as e:
        metrics.send('rotate_failure', 'counter', 1, metric_tags={'endpoint': endpoint.name})
        current_app.logger.exception(e)


def reissue_and_rotate(certificate):
    """
    Reissues and rotates a given certificate.
    :param certificate:
    :return:
    """
    new_cert = reissue_certificate(certificate, replace=True)

    for endpoint in certificate.endpoints:
        lemur.deployment.service.rotate_certificate(endpoint, new_cert)
