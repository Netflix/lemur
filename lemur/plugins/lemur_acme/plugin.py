"""
.. module: lemur.plugins.lemur_acme.acme
    :platform: Unix
    :synopsis: This module is responsible for communicating with a ACME CA.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

    Snippets from https://raw.githubusercontent.com/alex/letsencrypt-aws/master/letsencrypt-aws.py

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
.. moduleauthor:: Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>
"""
from flask import current_app

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from acme.client import Client
from acme import jose

import time
import itertools
from flask import current_app

from acme import messages

from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_acme as acme


def create_JWKRSA(pem):
    """
    Will parse the current private key pem and create a comparable JWKRSA token to be
    used to sign requests.
    :param pem:
    :return:
    """
    key = load_pem_private_key(pem, None, backend=default_backend())
    return jose.JWKRSA(key=jose.ComparableRSAKey(key))


def _get_domains(options):
    """
    Fetches all domains currently requested
    :param options:
    :return:
    """
    domains = [options['commonName']]
    for name in options['extensions']['subAltName']['names']:
        domains.append(name)
    return domains


def get_authorizations(domains, regr, best_effort=False):
    """Retrieve all authorizations for challenges.
    """
    dv_c = []
    cont_c = []

    authzr = dict()
    for domain in domains:
        authzr[domain] = acme.request_domain_challenges(
            domain, regr.new_authzr_uri)

    # While there are still challenges remaining...
    while dv_c or cont_c:
        cont_resp, dv_resp = _solve_challenges()
        current_app.logger.info("Waiting for verification...")

        # Send all Responses - this modifies dv_c and cont_c
        _respond(cont_resp, dv_resp, best_effort)

    # Just make sure all decisions are complete.
    verify_authzr_complete()
    # Only return valid authorizations
    return [authzr for authzr in authzr.values() if authzr.body.status == messages.STATUS_VALID]  # noqa


def verify_authzr_complete(authzr):
    """Verifies that all authorizations have been decided.
    :returns: Whether all authzr are complete
    :rtype: bool
    """
    for authzr in authzr.values():
        if (authzr.body.status != messages.STATUS_VALID and
                authzr.body.status != messages.STATUS_INVALID):
            raise Exception("Incomplete authorizations")


def _solve_challenges(dv_c):
    """Get Responses for challenges from authenticators."""
    dv_resp = []
    if dv_c:
        pass
        # dv_resp = dv_auth.perform(dv_c)

    assert len(dv_resp) == len(dv_c)

    return dv_resp


def _respond(cont_resp, dv_resp, dv_c, best_effort):
    """Send/Receive confirmation of all challenges.
    .. note:: This method also cleans up the auth_handler state.
    """
    chall_update = dict()
    active_achalls = []
    active_achalls.extend(
        _send_responses(dv_c, dv_resp, chall_update))

    # Check for updated status...
    _poll_challenges(chall_update, best_effort)


def _send_responses(self, achalls, resps, chall_update):
    """Send responses and make sure errors are handled.
    :param dict chall_update: parameter that is updated to hold
        authzr -> list of outstanding solved annotated challenges
    """
    active_achalls = []
    for achall, resp in itertools.izip(achalls, resps):
        # This line needs to be outside of the if block below to
        # ensure failed challenges are cleaned up correctly
        active_achalls.append(achall)

        # Don't send challenges for None and False authenticator responses
        if resp is not None and resp:
            acme.answer_challenge(achall.challb, resp)
            # TODO: answer_challenge returns challr, with URI,
            # that can be used in _find_updated_challr
            # comparisons...
            if achall.domain in chall_update:
                chall_update[achall.domain].append(achall)
            else:
                chall_update[achall.domain] = [achall]

    return active_achalls


def _poll_challenges(chall_update, best_effort, min_sleep=3, max_rounds=15):
    """Wait for all challenge results to be determined."""
    dom_to_check = set(chall_update.keys())
    comp_domains = set()
    rounds = 0

    while dom_to_check and rounds < max_rounds:
        # TODO: Use retry-after...
        time.sleep(min_sleep)
        all_failed_achalls = set()
        for domain in dom_to_check:
            comp_achalls, failed_achalls = _handle_check(
                domain, chall_update[domain])

            if len(comp_achalls) == len(chall_update[domain]):
                comp_domains.add(domain)
            elif not failed_achalls:
                for achall, _ in comp_achalls:
                    chall_update[domain].remove(achall)
            # We failed some challenges... damage control
            else:
                # Right now... just assume a loss and carry on...
                if best_effort:
                    comp_domains.add(domain)
                else:
                    all_failed_achalls.update(
                        updated for _, updated in failed_achalls)

        dom_to_check -= comp_domains
        comp_domains.clear()
        rounds += 1


def _handle_check(domain, authzr, achalls):
    """Returns tuple of ('completed', 'failed')."""
    completed = []
    failed = []

    authzr[domain], _ = acme.poll(authzr[domain])
    if authzr[domain].body.status == messages.STATUS_VALID:
        return achalls, []

        # Note: if the whole authorization is invalid, the individual failed
        #     challenges will be determined here...
        # for achall in achalls:
        #    updated_achall = achall.update(challb=_find_updated_challb(
        #        authzr[domain], achall))

        # This does nothing for challenges that have yet to be decided yet.
        # if updated_achall.status == messages.STATUS_VALID:
        #     completed.append((achall, updated_achall))
        # elif updated_achall.status == messages.STATUS_INVALID:
        #     failed.append((achall, updated_achall))

    return completed, failed


class ACMEIssuerPlugin(IssuerPlugin):
    title = 'Acme'
    slug = 'acme-issuer'
    description = 'Enables the creation of certificates via ACME CAs (including Let\'s Encrypt'
    version = acme.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur.git'

    def __init__(self, *args, **kwargs):
        self.key = create_JWKRSA(current_app.config.get('ACME_PRIVATE_KEY').strip())
        self.acme_uri = current_app.config.get('ACME_URL')
        self.authzr_uri = '{}/acme/authz/1'.format(self.acme_uri)
        self.acme_email = current_app.config.get('ACME_EMAIL')
        self.acme_tel = current_app.config.get('ACME_TEL')
        self.contact = ('mailto:{}'.format(self.acme_email), 'tel:{}'.format(self.acme_tel))

        current_app.logger.debug("Registering with Lets Encrypt")

        directory = messages.Directory({
            messages.NewRegistration: '{}/acme/new-reg'.format(self.acme_uri),
            messages.Revocation: '{}/acme/revoke-cert'.format(self.acme_uri),
        })

        self.client = Client(directory=directory, key=self.key, alg=jose.RS256)
        super(ACMEIssuerPlugin, self).__init__(*args, **kwargs)

    @staticmethod
    def _get_domains(options):
        """
        Fetches all domains currently requested
        :param options:
        :return:
        """
        domains = [options['commonName']]
        for name in options['extensions']['subAltName']['names']:
            domains.append(name)
        return domains

    def _get_challenges(self, options):
        domains = self._get_domains(options)
        challenges = dict()
        for domain in domains:
            challenges[domain] = self.client.request_domain_challenges(domain, self.authzr_uri)
        return challenges

    @staticmethod
    def _solve_challenges(self, challenges):
        for chall in challenges:
            print chall.token

    def create_certificate(self, csr, issuer_options):
        """
        Creates a ACME certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        # Registration
        regr = self.client.register()
        regr.body.update(agreement=regr.terms_of_service, key=self.key, contact=self.contact)
        self.client.update_registration(regr, regr.update(body=regr.body))
        self.client.agree_to_tos(regr)

        challs = self._get_challenges(issuer_options)
        authzrs = self.solve_challenges(challs)

        cert = self.client.poll_and_request_issuance(csr, authzrs)

        current_app.logger.debug("Requesting a new acme certificate: {0}".format(issuer_options))
        current_app.logger.debug("Registering with Lets Encrypt")
        regr = acme.register()
        acme.update_registration(regr.update(body=regr.body.update(agreement=regr.terms_of_service)))

        # get authorizations for each domain in SAN
        domains = _get_domains(issuer_options)
        authz = get_authorizations(domains)

        current_app.logger.debug("Requesting a new acme certificate: {0}".format(issuer_options))
        cert = acme.request_issuance(csr, (authz,))

        return cert, acme.fetch_chain(cert)

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        role = {'username': '', 'password': '', 'name': 'acme'}
        return current_app.config.get('ACME_ROOT'), "", [role]
