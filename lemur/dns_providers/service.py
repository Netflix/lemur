import json

from flask import current_app
from lemur import database
from lemur.dns_providers.models import DnsProviders


def render(args):
    """
    Helper that helps us render the REST Api responses.
    :param args:
    :return:
    """
    query = database.session_query(DnsProviders)

    return database.sort_and_page(query, DnsProviders, args)


def get(dns_provider_id):
    """
    Retrieves a dns provider by its lemur assigned ID.

    :param dns_provider_id: Lemur assigned ID
    :rtype : DnsProvider
    :return:
    """
    return database.get(DnsProviders, dns_provider_id)


def delete(dns_provider_id):
    """
    Deletes a DNS provider.

    :param dns_provider_id: Lemur assigned ID
    """
    database.delete(get(dns_provider_id))


def get_types():
    provider_config = current_app.config.get('ACME_DNS_PROVIDER_TYPES')
    if not provider_config:
        raise Exception("No DNS Provider configuration specified.")
    return provider_config
