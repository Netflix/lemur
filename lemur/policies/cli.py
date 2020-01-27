"""
.. module: lemur.policies.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask_script import Manager
from lemur.policies import service as policy_service


manager = Manager(usage="Handles all policy related tasks.")


@manager.option("-d", "--days", dest="days", help="Number of days before expiration.")
@manager.option("-n", "--name", dest="name", help="Policy name.")
def create(days, name):
    """
    Create a new certificate rotation policy
    :return:
    """
    print("[+] Creating a new certificate rotation policy.")
    policy_service.create(days=days, name=name)
    print("[+] Successfully created a new certificate rotation policy")
