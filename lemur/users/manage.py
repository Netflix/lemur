"""
.. module: lemur.users.manage
    :copyright: (c) 2015 by netflix inc., see authors for more
    :license: apache, see license for more details.
.. moduleauthor:: kevin glisson <kglisson@netflix.com>
"""
import sys
from tabulate import tabulate

from flask.ext.script import Manager, Command, Option, prompt_pass

from lemur.roles import service as role_service
from lemur.exceptions import DuplicateError
from .service import create, get_all

manager = Manager(usage="Perform role operations")


class Create(Command):
    """
    This command allows for the creation of a new role within Lemur
    """
    option_list = (
        Option('-n', '--name', dest='name', required=True),
        Option('-e', '--email', dest='email', required=True),
        Option('-r', '--roles', dest='roles', default=[])
    )

    def run(self, name, email, roles):
        role_objs = []
        for u in roles:
            role_obj = role_service.get_by_rolename(u)
            if role_obj:
                role_objs.append(role_obj)
            else:
                print("[!] Cannot find role {0}".format(u))
                sys.exit(1)

        p1 = prompt_pass("Enter Password")
        p2 = prompt_pass("Confirm Password")

        if p1 != p2:
            print("[\] Passwords do not match")
            sys.exit(1)

        try:
            create(name, p1, email, True, None, roles)
            print("[+] Created new user: {0}".format(name))
        except DuplicateError:
            print("[\] Username {0} already exists".format(name))


@manager.command
def list():
    """
    Lists all available roles

    :return:
    """
    users = get_all()
    table = [["User Name", "Email", "Active"]]
    for r in users:
        table.append([r.username, r.email, r.active])

    print(tabulate(table))


manager.add_command("create", Create())
