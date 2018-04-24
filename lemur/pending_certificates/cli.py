"""
.. module: lemur.pending_certificates.cli

.. moduleauthor:: James Chuong <jchuong@instartlogic.com>
"""

from flask_script import Manager

from lemur.pending_certificates import service as pending_certificate_service
from lemur.plugins.base import plugins
from lemur.users import service as user_service

manager = Manager(usage="Handles pending certificate related tasks.")


@manager.option('-i', dest='ids', action='append', help='IDs of pending certificates to fetch')
def fetch(ids):
    """
    Attempt to get full certificates for each pending certificate listed.

    Args:
        ids: a list of ids of PendingCertificates (passed in by manager options when run as CLI)
             `python manager.py pending_certs fetch -i 123 321 all`
    """
    new = 0
    failed = 0
    pending_certs = pending_certificate_service.get_pending_certs(ids)
    user = user_service.get_by_username('lemur')

    for cert in pending_certs:
        authority = plugins.get(cert.authority.plugin_name)
        real_cert = authority.get_ordered_certificate(cert)
        if real_cert:
            # If a real certificate was returned from issuer, then create it in Lemur and delete
            # the pending certificate
            pending_certificate_service.create_certificate(cert, real_cert, user)
            pending_certificate_service.delete(cert)
            # add metrics to metrics extension
            new += 1
        else:
            pending_certificate_service.increment_attempt(cert)
            failed += 1
    print(
        "[+] Certificates: New: {new} Failed: {failed}".format(
            new=new,
            failed=failed
        )
    )
