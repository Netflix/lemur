import time
import json

from flask_script import Manager
from flask import current_app

from lemur.extensions import sentry
from lemur.constants import SUCCESS_METRIC_STATUS
from lemur.plugins.lemur_acme.plugin import AcmeHandler

manager = Manager(
    usage="Handles all ACME related tasks"
)


@manager.option(
    "-d",
    "--domain",
    dest="domain",
    required=True,
    help="Name of the Domain to store to (ex. \"_acme-chall.test.com\".",
)
@manager.option(
    "-t",
    "--token",
    dest="token",
    required=True,
    help="Value of the Token to store in DNS as content.",
)
def dnstest(domain, token):
    """
    Create, verify, and delete DNS TXT records using an autodetected provider.
    """
    print("[+] Starting ACME Tests.")
    change_id = (domain, token)

    acme_handler = AcmeHandler()
    acme_handler.autodetect_dns_providers(domain)
    if not acme_handler.dns_providers_for_domain[domain]:
        raise Exception(f"No DNS providers found for domain: {format(domain)}.")

    # Create TXT Records
    for dns_provider in acme_handler.dns_providers_for_domain[domain]:
        dns_provider_plugin = acme_handler.get_dns_provider(dns_provider.provider_type)
        dns_provider_options = json.loads(dns_provider.credentials)
        account_number = dns_provider_options.get("account_id")

        print(f"[+] Creating TXT Record in `{dns_provider.name}` provider")
        change_id = dns_provider_plugin.create_txt_record(domain, token, account_number)

    print("[+] Verifying TXT Record has propagated to DNS.")
    print("[+] This step could take a while...")
    time.sleep(10)

    # Verify TXT Records
    for dns_provider in acme_handler.dns_providers_for_domain[domain]:
        dns_provider_plugin = acme_handler.get_dns_provider(dns_provider.provider_type)
        dns_provider_options = json.loads(dns_provider.credentials)
        account_number = dns_provider_options.get("account_id")

        try:
            dns_provider_plugin.wait_for_dns_change(change_id, account_number)
            print(f"[+] Verified TXT Record in `{dns_provider.name}` provider")
        except Exception:
            sentry.captureException()
            current_app.logger.debug(
                f"Unable to resolve DNS challenge for change_id: {change_id}, account_id: "
                f"{account_number}",
                exc_info=True,
            )
            print(f"[+] Unable to Verify TXT Record in `{dns_provider.name}` provider")

    time.sleep(10)

    # Delete TXT Records
    for dns_provider in acme_handler.dns_providers_for_domain[domain]:
        dns_provider_plugin = acme_handler.get_dns_provider(dns_provider.provider_type)
        dns_provider_options = json.loads(dns_provider.credentials)
        account_number = dns_provider_options.get("account_id")

        # TODO(csine@: Add Exception Handling
        dns_provider_plugin.delete_txt_record(change_id, account_number, domain, token)
        print(f"[+] Deleted TXT Record in `{dns_provider.name}` provider")

    status = SUCCESS_METRIC_STATUS
    print("[+] Done with ACME Tests.")
