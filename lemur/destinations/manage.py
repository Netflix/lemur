"""
.. module: lemur.destination.manage
    :copyright: (c) 2015 by netflix inc., see authors for more
    :license: apache, see license for more details.
.. moduleauthor:: kevin glisson <kglisson@netflix.com>
"""
from flask.ext.script import Manager, Command, Option

from .service import create


manager = Manager(usage="Perform role operations")


class Create(Command):
    """
    This command allows for the creation of a new role within Lemur
    """
    option_list = (
        Option('-n', '--name', dest='name', required=True),
        Option('-d', '--description', dest='description', required=True)
    )

    def run(self, name, description):
        create(name, description=description)
        print("[+] Created new destination: {0}".format(name))


@manager.command
def list():
    """
    Lists all the available roles

    :return:
    """
    pass


manager.add_command("create", Create())
