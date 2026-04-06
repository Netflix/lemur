import logging

from lemur import database

logger = logging.getLogger(__name__)


def rotate_certificate(endpoint, new_cert):
    """
    Rotates a certificate on a given endpoint.

    :param endpoint:
    :param new_cert:
    :return:
    """
    old_cert = endpoint.certificate

    # ensure that certificate is available for rotation
    endpoint.source.plugin.update_endpoint(endpoint, new_cert)
    endpoint.certificate = new_cert
    database.update(endpoint)

    # attempt to detach the old certificate from the endpoint
    if old_cert and old_cert.name != new_cert.name:
        try:
            endpoint.source.plugin.remove_old_certificate(endpoint, old_cert)
        except Exception:
            logger.warning(
                "Failed to remove old certificate %s from endpoint %s",
                old_cert.name,
                endpoint.name,
            )
