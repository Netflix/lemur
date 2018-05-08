"""
.. module: lemur.pending_certificates.cli

.. moduleauthor:: James Chuong <jchuong@instartlogic.com>
.. moduleauthor:: Curtis Castrapel <ccastrapel@netflix.com>
"""
from flask_script import Manager

from lemur.authorities.service import get as get_authority
from lemur.pending_certificates import service as pending_certificate_service
from lemur.plugins.base import plugins
from lemur.users import service as user_service

manager = Manager(usage="Handles pending certificate related tasks.")


# Need to call this multiple times and store status of the cert in DB. If it is being worked on by a worker, and which
# worker.
# Then open up an arbitrary number of copies of this? every minute??
# Or instead how about you send in a list of all pending certificates, make all the dns changes at once, then loop
# through and wait for each one to complete?
@manager.option('-i', dest='ids', action='append', help='IDs of pending certificates to fetch')
def fetch(ids):
    """
    Attempt to get full certificates for each pending certificate listed.

    Args:
        ids: a list of ids of PendingCertificates (passed in by manager options when run as CLI)
             `python manager.py pending_certs fetch -i 123 321 all`
    """
    pending_certs = pending_certificate_service.get_pending_certs(ids)
    user = user_service.get_by_username('lemur')
    new = 0
    failed = 0

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
            failed=failed,
        )
    )


@manager.command
def fetch_all_acme():
    """
    Attempt to get full certificates for each pending certificate listed with the acme-issuer. This is more efficient
    for acme-issued certificates because it will configure all of the DNS challenges prior to resolving any
    certificates.
    """
    pending_certs = pending_certificate_service.get_pending_certs('all')
    user = user_service.get_by_username('lemur')
    new = 0
    failed = 0
    wrong_issuer = 0
    acme_certs = []

    # We only care about certs using the acme-issuer plugin
    for cert in pending_certs:
        cert_authority = get_authority(cert.authority_id)
        if cert_authority.plugin_name == 'acme-issuer':
            acme_certs.append(cert)
        else:
            wrong_issuer += 1

    authority = plugins.get("acme-issuer")
    resolved_certs = authority.get_ordered_certificates(acme_certs)

    for cert in resolved_certs:
        real_cert = cert.get("cert")
        # It's necessary to reload the pending cert due to detached instance: http://sqlalche.me/e/bhk3
        pending_cert = pending_certificate_service.get(cert.get("pending_cert").id)

        if real_cert:
            # If a real certificate was returned from issuer, then create it in Lemur and delete
            # the pending certificate
            pending_certificate_service.create_certificate(pending_cert, real_cert, user)
            pending_certificate_service.delete_by_id(pending_cert.id)
            # add metrics to metrics extension
            new += 1
        else:
            pending_certificate_service.increment_attempt(pending_cert)
            failed += 1
    print(
        "[+] Certificates: New: {new} Failed: {failed} Not using ACME: {wrong_issuer}".format(
            new=new,
            failed=failed,
            wrong_issuer=wrong_issuer
        )
    )
