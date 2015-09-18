"""
.. module: lemur.destination.manage
    :copyright: (c) 2015 by netflix inc., see authors for more
    :license: apache, see license for more details.
.. moduleauthor:: kevin glisson <kglisson@netflix.com>
"""
import json
from tabulate import tabulate
from flask.ext.script import Manager

from .service import get_all


manager = Manager(usage="Perform role operations")


@manager.command
def list():
    """
    Lists all the available roles

    :return:
    """
    destinations = get_all()
    table = [["Label", "Description", "Options"]]
    for r in destinations:
        table.append([r.label, r.description, json.dumps(r.options)])

    print(tabulate(table))
