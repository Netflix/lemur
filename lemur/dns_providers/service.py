import json

from flask import current_app

from lemur import database
from lemur.dns_providers.models import DnsProvider
from lemur.logs import service as log_service


def render(args):
    """
    Helper that helps us render the REST Api responses.
    :param args:
    :return:
    """
    query = database.session_query(DnsProvider)

    return database.sort_and_page(query, DnsProvider, args)


def get(dns_provider_id):
    provider = database.get(DnsProvider, dns_provider_id)
    return provider


def get_all_dns_providers():
    """
    Retrieves all dns providers within Lemur.

    :return:
    """
    return DnsProvider.query.all()


def get_friendly(dns_provider_id):
    """
    Retrieves a dns provider by its lemur assigned ID.

    :param dns_provider_id: Lemur assigned ID
    :rtype: DnsProvider
    :return:
    """
    dns_provider = get(dns_provider_id)
    if not dns_provider:
        return None
    dns_provider_friendly = {
        "name": dns_provider.name,
        "description": dns_provider.description,
        "providerType": dns_provider.provider_type,
        "options": dns_provider.options,
        "credentials": dns_provider.credentials,
    }

    if dns_provider.provider_type == "route53":
        dns_provider_friendly["account_id"] = json.loads(dns_provider.credentials).get(
            "account_id"
        )
    return dns_provider_friendly


def delete(dns_provider_id):
    """
    Deletes a DNS provider.

    :param dns_provider_id: Lemur assigned ID
    """
    dns_provider = get(dns_provider_id)
    if dns_provider:
        log_service.audit_log("delete_dns_provider", dns_provider.name, "Deleting the DNS provider")
        database.delete(dns_provider)


def get_types():
    provider_config = current_app.config.get(
        "ACME_DNS_PROVIDER_TYPES",
        {
            "items": [
                {
                    "name": "route53",
                    "requirements": [
                        {
                            "name": "account_id",
                            "type": "int",
                            "required": True,
                            "helpMessage": "AWS Account number",
                        }
                    ],
                },
                {
                    "name": "cloudflare",
                    "requirements": [
                        {
                            "name": "email",
                            "type": "str",
                            "required": True,
                            "helpMessage": "Cloudflare Email",
                        },
                        {
                            "name": "key",
                            "type": "str",
                            "required": True,
                            "helpMessage": "Cloudflare Key",
                        },
                    ],
                },
                {"name": "dyn"},
                {"name": "nsone"},
                {"name": "ultradns"},
                {"name": "powerdns"},
            ]
        },
    )
    if not provider_config:
        raise Exception("No DNS Provider configuration specified.")
    provider_config["total"] = len(provider_config.get("items"))
    return provider_config


def set_domains(dns_provider, domains):
    """
    Increments pending certificate attempt counter and updates it in the database.
    """
    dns_provider.domains = domains
    database.update(dns_provider)
    return dns_provider


def create(data):
    provider_name = data.get("name")

    credentials = {}
    for item in data.get("provider_type", {}).get("requirements", []):
        credentials[item["name"]] = item["value"]
    dns_provider = DnsProvider(
        name=provider_name,
        description=data.get("description"),
        provider_type=data.get("provider_type").get("name"),
        credentials=json.dumps(credentials),
    )
    created = database.create(dns_provider)

    log_service.audit_log("create_dns_provider", provider_name, "Created new DNS provider")
    return created.id
