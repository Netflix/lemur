"""
Debugging hooks for dumping imported or generated CSR and certificate details to stdout via OpenSSL.

.. module: lemur.certificates.hooks
    :platform: Unix
    :copyright: (c) 2018 by Marti Raudsepp, see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Marti Raudsepp <marti@juffo.org>
"""
import subprocess

from flask import current_app

from lemur.certificates.service import (
    csr_created,
    csr_imported,
    certificate_issued,
    certificate_imported,
)


def csr_dump_handler(sender, csr, **kwargs):
    try:
        subprocess.run(
            ["openssl", "req", "-text", "-noout", "-reqopt", "no_sigdump,no_pubkey"],
            input=csr.encode("utf8"),
        )
    except Exception as err:
        current_app.logger.warning("Error inspecting CSR: %s", err)


def cert_dump_handler(sender, certificate, **kwargs):
    try:
        subprocess.run(
            ["openssl", "x509", "-text", "-noout", "-certopt", "no_sigdump,no_pubkey"],
            input=certificate.body.encode("utf8"),
        )
    except Exception as err:
        current_app.logger.warning("Error inspecting certificate: %s", err)


def activate_debug_dump():
    csr_created.connect(csr_dump_handler)
    csr_imported.connect(csr_dump_handler)
    certificate_issued.connect(cert_dump_handler)
    certificate_imported.connect(cert_dump_handler)
