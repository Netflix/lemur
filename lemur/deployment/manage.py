"""
.. module: lemur.deployment.manage
    :copyright: (c) 2015 by netflix inc., see authors for more
    :license: apache, see license for more details.
.. moduleauthor:: kevin glisson <kglisson@netflix.com>
"""
from flask.ext.script import Manager

from lemur.plugins.lemur_aws.manage import manager as elb_manager

manager = Manager(usage="Perform deployment operations")

# TODO generalize this so that any destination plugin can declare a manager
manager.add_command("elb", elb_manager)
