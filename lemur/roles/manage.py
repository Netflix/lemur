"""
.. module: lemur.roles.manage
    :copyright: (c) 2015 by netflix inc., see authors for more
    :license: apache, see license for more details.
.. moduleauthor:: kevin glisson <kglisson@netflix.com>
"""
import sys
from tabulate import tabulate

from flask.ext.script import Manager, Command, Option

from lemur.users import service as user_service
from lemur.exceptions import DuplicateError
from .service import create, get_all

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
        try:
            create(name, description=description, users=users)
            print("[+] Created new role: {0}".format(name))
        except DuplicateError:
            print("[\] Role name {0} already exists".format(name))


@manager.command
def list():
    """
    Lists all available roles

    :return:
    """
    roles = get_all()
    table = [["Name", "Description"]]
    for r in roles:
        table.append([r.name, r.description])

    print(tabulate(table))


manager.add_command("create", Create())
