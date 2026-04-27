import logging

from flask import current_app

from lemur import database

logger = logging.getLogger(__name__)


def rotate_certificate(endpoint, old_cert, new_cert):
    """
    Rotates a certificate on a given endpoint.

    :param endpoint:
    :param old_cert:
    :param new_cert:
    :return:
    """
    sni_rotation = old_cert in endpoint.sni_certificates
    if sni_rotation and endpoint.primary_certificate == old_cert:
        current_app.logger.warn(
            f"{old_cert.name} attached to endpoint {endpoint.name} as both primary "
            "and SNI certificate which is likely unnecessary"
        )
        _rotate_primary_certificate(endpoint, new_cert)
    elif sni_rotation:
        _rotate_sni_certificate(endpoint, old_cert, new_cert)
    else:
        _rotate_primary_certificate(endpoint, new_cert)
    database.update(endpoint)


def _rotate_primary_certificate(endpoint, new_cert):
    """
    Rotates the primary certificate on a given endpoint.

    :param endpoint:
    :param new_cert:
    :return:
    """
    old_cert = endpoint.primary_certificate

    # ensure that certificate is available for rotation
    endpoint.source.plugin.update_endpoint(endpoint, new_cert)
    endpoint.primary_certificate = new_cert

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


def _rotate_sni_certificate(endpoint, old_cert, new_cert):
    """
    Rotates a SNI certificate on a given endpoint.

    :param endpoint:
    :param old_cert:
    :param new_cert:
    :return:
    """
    endpoint.source.plugin.replace_sni_certificate(endpoint, old_cert, new_cert)
    endpoint.replace_sni_certificate(old_cert, new_cert)
