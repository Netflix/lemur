"""
.. module: lemur.plugins.bases.issuer
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.base import Plugin


class IssuerPlugin(Plugin):
    """
    This is the base class from which all of the supported
    issuers will inherit from.
    """

    type = "issuer"

    def create_certificate(self, csr, issuer_options):
        raise NotImplementedError

    def create_authority(self, options):
        raise NotImplementedError

    def revoke_certificate(self, certificate, reason):
        raise NotImplementedError

    def get_ordered_certificate(self, certificate):
        raise NotImplementedError

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        raise NotImplementedError

    def deactivate_certificate(self, certificate):
        raise NotImplementedError

    @property
    def allows_auto_resolve(self) -> bool:
        """
        Some issuers, such as the manual issuer, do not allow for auto-resolve
        of pending certificates. This method allows plugins to indicate that they allow
        auto-resolve, which will prevent Lemur from automatically calling fetch_acme_cert.apply_async.
        """
        return True
