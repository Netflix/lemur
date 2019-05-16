"""
.. module: lemur.api_keys.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Eric Coan <kungfury@instructure.com>
"""
from flask_script import Manager
from lemur.api_keys import service as api_key_service
from lemur.auth.service import create_token

from datetime import datetime

manager = Manager(usage="Handles all api key related tasks.")


@manager.option(
    "-u", "--user-id", dest="uid", help="The User ID this access key belongs too."
)
@manager.option("-n", "--name", dest="name", help="The name of this API Key.")
@manager.option(
    "-t", "--ttl", dest="ttl", help="The TTL of this API Key. -1 for forever."
)
def create(uid, name, ttl):
    """
    Create a new api key for a user.
    :return:
    """
    print("[+] Creating a new api key.")
    key = api_key_service.create(
        user_id=uid,
        name=name,
        ttl=ttl,
        issued_at=int(datetime.utcnow().timestamp()),
        revoked=False,
    )
    print("[+] Successfully created a new api key. Generating a JWT...")
    jwt = create_token(uid, key.id, key.ttl)
    print("[+] Your JWT is: {jwt}".format(jwt=jwt))


@manager.option("-a", "--api-key-id", dest="aid", help="The API Key ID to revoke.")
def revoke(aid):
    """
    Revokes an api key for a user.
    :return:
    """
    print("[-] Revoking the API Key api key.")
    api_key_service.revoke(aid=aid)
    print("[+] Successfully revoked the api key")
