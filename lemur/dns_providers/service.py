from lemur.dns_providers.models import DnsProviders


def get_all_dns_providers(status="active"):
    """
    Retrieves all certificates within Lemur.

    :return:
    """
    all_dns_providers = DnsProviders.query.all()
    dns_provider_result = []
    for provider in all_dns_providers:
        print(provider)
        if provider.status == status:
            dns_provider_result.append(provider.__dict__)
    return dns_provider_result
