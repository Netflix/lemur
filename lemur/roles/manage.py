"""
.. module: lemur.roles.manage
    :copyright: (c) 2015 by netflix inc., see authors for more
    :license: apache, see license for more details.
.. moduleauthor:: kevin glisson <kglisson@netflix.com>
"""
import sys
from flask.ext.script import Manager, Command, Option

from lemur.users import service as user_service

from .service import create


manager = Manager(usage="Perform role operations")


class Create(Command):
    """
    This command allows for the creation of a new role within Lemur
    """
    option_list = (
        Option('-n', '--name', dest='name', required=True),
        Option('-u', '--users', dest='users', default=[]),
        Option('-d', '--description', dest='description', required=True)
    )

    def run(self, name, users, description):
        user_objs = []
        for u in users:
            user_obj = user_service.get_by_username(u)
            if user_obj:
                user_objs.append(user_obj)
            else:
                print("[!] Cannot find user {0}".format(u))
                sys.exit(1)
        create(name, description=description, users=users)
        print("[+] Created new role: {0}".format(name))


@manager.command
def list():
    """
    Lists all available roles

    :return:
    """
    pass

manager.add_command("create", Create())
