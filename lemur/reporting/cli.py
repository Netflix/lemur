"""
.. module: lemur.reporting.cli
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from tabulate import tabulate
from flask_script import Manager

from lemur.reporting.service import fqdns

manager = Manager(usage="Reporting related tasks.")


@manager.option('-d', '--deployed', dest='deployed', help='Filter by certificates deployed onto endpoints.')
@manager.option('-e', '--expired', dest='expired', help='Include certificates that are currently expired.')
def fqdn(deployed, expired):
    """
    Generates a report in order to determine the number of FQDNs covered by Lemur issued certificates.
    """
    headers = ['FQDN', 'Root Domain', 'Issuer', 'Total Length (days), Time Until Expiration (days)']
    rows = []

    for row in fqdns(expired=expired, deployed=deployed):
        rows.append(row)

    print(tabulate(rows, header=headers))
