"""
.. module: lemur.policies.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import click

from lemur.policies import service as policy_service


@click.group(name="policy", help="Handles all policy related tasks.")
def cli():
    pass


@cli.command("create")
@click.option("-d", "--days", "days", help="Number of days before expiration.")
@click.option("-n", "--name", "name", help="Policy name.")
def create_command(days, name):
    create(days, name)


def create(days, name):
    """
    Create a new certificate rotation policy
    :return:
    """
    click.echo("[+] Creating a new certificate rotation policy.")
    policy_service.create(days=days, name=name)
    click.echo("[+] Successfully created a new certificate rotation policy")
