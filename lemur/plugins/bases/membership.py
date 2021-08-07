"""
.. module: lemur.plugins.bases.membership
    :platform: Unix
    :copyright: (c) 2021 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Sayali Charhate <scharhate@netflix.com>
"""
from lemur.plugins.base import Plugin


class MembershipPlugin(Plugin):
    """
    This is the base class for membership API providers.
    """
    type = "membership"

    # check if principal exists as a user or a group (Team DL)
    def does_principal_exist(self, principal_email):
        raise NotImplementedError

    # check if a group (Team DL) exists
    def does_group_exist(self, group_email):
        raise NotImplementedError

    # get a list of groups a user belongs to
    def retrieve_user_memberships(self, user_id):
        raise NotImplementedError
