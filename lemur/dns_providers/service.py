from lemur.dns_providers.models import DnsProviders


def get_all_dns_providers(status="active"):
    """
    Retrieves all certificates within Lemur.

    :return:
    """
    return DnsProviders.query.all(status=status)