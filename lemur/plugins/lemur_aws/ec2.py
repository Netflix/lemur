"""
.. module: lemur.plugins.lemur_aws.elb
    :synopsis: Module contains some often used and helpful classes that
    are used to deal with ELBs

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.lemur_aws.sts import sts_client


@sts_client('ec2')
def get_all_instances(**kwargs):
    """
    Fetches all instance objects for a given account and region.
    """
    paginator = kwargs['client'].get_paginator('describe_instances')
    return paginator.paginate()
