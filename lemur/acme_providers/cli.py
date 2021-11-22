import time
import json
import arrow

from flask_script import Manager
from flask import current_app

from sentry_sdk import capture_exception
from lemur.common.utils import check_validation
from lemur.constants import SUCCESS_METRIC_STATUS
from lemur.plugins import plugins
from lemur.plugins.lemur_acme.plugin import AcmeHandler
from lemur.plugins.lemur_aws import s3

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
            capture_exception()
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


@manager.option(
    "-t",
    "--token",
    dest="token",
    default="date: " + arrow.utcnow().format("YYYY-MM-DDTHH-mm-ss"),
    required=False,
    help="Value of the Token",
)
@manager.option(
    "-n",
    "--token_name",
    dest="token_name",
    default="Token-" + arrow.utcnow().format("YYYY-MM-DDTHH-mm-ss"),
    required=False,
    help="path",
)
@manager.option(
    "-p",
    "--prefix",
    dest="prefix",
    default="test/",
    required=False,
    help="S3 bucket prefix",
)
@manager.option(
    "-a",
    "--account_number",
    dest="account_number",
    required=True,
    help="AWS Account",
)
@manager.option(
    "-b",
    "--bucket_name",
    dest="bucket_name",
    required=True,
    help="Bucket Name",
)
def upload_acme_token_s3(token, token_name, prefix, account_number, bucket_name):
    """
    This method serves for testing the upload_acme_token to S3, fetching the token to verify it, and then deleting it.
    It mainly serves for testing purposes.
    :param token:
    :param token_name:
    :param prefix:
    :param account_number:
    :param bucket_name:
    :return:
    """
    additional_options = [
        {
            "name": "bucket",
            "value": bucket_name,
            "type": "str",
            "required": True,
            "validation": check_validation(r"[0-9a-z.-]{3,63}"),
            "helpMessage": "Must be a valid S3 bucket name!",
        },
        {
            "name": "accountNumber",
            "type": "str",
            "value": account_number,
            "required": True,
            "validation": check_validation(r"[0-9]{12}"),
            "helpMessage": "A valid AWS account number with permission to access S3",
        },
        {
            "name": "region",
            "type": "str",
            "default": "us-east-1",
            "required": False,
            "helpMessage": "Region bucket exists",
            "available": ["us-east-1", "us-west-2", "eu-west-1"],
        },
        {
            "name": "encrypt",
            "type": "bool",
            "value": False,
            "required": False,
            "helpMessage": "Enable server side encryption",
            "default": True,
        },
        {
            "name": "prefix",
            "type": "str",
            "value": prefix,
            "required": False,
            "helpMessage": "Must be a valid S3 object prefix!",
        },
    ]

    p = plugins.get("aws-s3")
    p.upload_acme_token(token_name, token, additional_options)

    if not prefix.endswith("/"):
        prefix + "/"

    token_res = s3.get(bucket_name, prefix + token_name, account_number=account_number)
    assert(token_res == token)
    s3.delete(bucket_name, prefix + token_name, account_number=account_number)
