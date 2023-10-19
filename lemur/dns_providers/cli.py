import sys
import click

from sentry_sdk import capture_exception

from lemur.constants import SUCCESS_METRIC_STATUS
from lemur.plugins.lemur_acme.acme_handlers import AcmeDnsHandler
from lemur.dns_providers.service import get_all_dns_providers, set_domains
from lemur.extensions import metrics


@click.group(name="dns_providers", help="Iterates through all DNS providers and sets DNS zones in the database.")
def cli():
    pass


@cli.command("get_all_zones")
def get_all_zones_command():
    get_all_zones()


def get_all_zones():
    """
    Retrieves all DNS providers from the database. Refreshes the zones associated with each DNS provider
    """
    click.echo("[+] Starting dns provider zone lookup and configuration.")
    dns_providers = get_all_dns_providers()
    acme_dns_handler = AcmeDnsHandler()

    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    log_data = {
        "function": function,
        "message": "",
    }

    for dns_provider in dns_providers:
        try:
            zones = acme_dns_handler.get_all_zones(dns_provider)
            set_domains(dns_provider, zones)
        except Exception as e:
            click.echo(f"[+] Error with DNS Provider {dns_provider.name}: {e}")
            log_data["message"] = f"get all zones failed for {dns_provider} {e}."
            capture_exception(extra=log_data)

    status = SUCCESS_METRIC_STATUS

    metrics.send("get_all_zones", "counter", 1, metric_tags={"status": status})
    click.echo("[+] Done with dns provider zone lookup and configuration.")
