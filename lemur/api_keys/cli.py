"""
.. module: lemur.api_keys.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Eric Coan <kungfury@instructure.com>
"""
import click

from lemur.api_keys import service as api_key_service
from lemur.auth.service import create_token

from datetime import datetime


@click.group(name="api_keys", help="Handles all api key related tasks.")
def cli():
    pass


@cli.command("create")
@click.option(
    "-u", "--user-id", "uid", help="The User ID this access key belongs too."
)
@click.option("-n", "--name", "name", help="The name of this API Key.")
@click.option(
    "-t", "--ttl", "ttl", help="The TTL of this API Key. -1 for forever."
)
def create_command(uid, name, ttl):
    create(uid, name, ttl)


def create(uid, name, ttl):
    """
    Create a new api key for a user.
    :return:
    """
    click.echo("[+] Creating a new api key.")
    key = api_key_service.create(
        user_id=uid,
        name=name,
        ttl=ttl,
        issued_at=int(datetime.utcnow().timestamp()),
        revoked=False,
    )
    click.echo("[+] Successfully created a new api key. Generating a JWT...")
    jwt = create_token(uid, key.id, key.ttl)
    click.echo(f"[+] Your JWT is: {jwt}")


@cli.command("revoke")
@click.option("-a", "--api-key-id", "aid", help="The API Key ID to revoke.")
def revoke_command(aid):
    revoke(aid)


def revoke(aid):
    """
    Revokes an api key for a user.
    :return:
    """
    click.echo("[-] Revoking the API Key api key.")
    api_key_service.revoke(aid=aid)
    click.echo("[+] Successfully revoked the api key")
