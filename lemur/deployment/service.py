from flask import current_app
from lemur import database


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
    endpoint.source.plugin.update_endpoint(endpoint, new_cert)
    endpoint.primary_certificate = new_cert


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
