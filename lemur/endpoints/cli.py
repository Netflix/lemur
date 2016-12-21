"""
.. module: lemur.endpoints.cli
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask_script import Manager

import arrow
from datetime import timedelta

from sqlalchemy import cast
from sqlalchemy_utils import ArrowType

from lemur import database
from lemur.extensions import metrics
from lemur.endpoints.models import Endpoint


manager = Manager(usage="Handles all endpoint related tasks.")


@manager.option('-ttl', '--time-to-live', type=int, dest='ttl', default=2, help='Time in hours, which endpoint has not been refreshed to remove the endpoint.')
def expire(ttl):
    """
    Removed all endpoints that have not been recently updated.
    """
    print("[+] Staring expiration of old endpoints.")
    now = arrow.utcnow()
    expiration = now - timedelta(hours=ttl)
    endpoints = database.session_query(Endpoint).filter(cast(Endpoint.last_updated, ArrowType) <= expiration)

    for endpoint in endpoints:
        print("[!] Expiring endpoint: {name} Last Updated: {last_updated}".format(name=endpoint.name, last_updated=endpoint.last_updated))
        database.delete(endpoint)
        metrics.send('endpoint_expired', 'counter', 1)

    print("[+] Finished expiration.")
