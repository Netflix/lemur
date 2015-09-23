"""
.. module: lemur.common.services.aws.sts
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import boto
import boto.ec2.elb

from flask import current_app


def assume_service(account_number, service, region=None):
    conn = boto.connect_sts()

    role = conn.assume_role('arn:aws:iam::{0}:role/{1}'.format(
        account_number, current_app.config.get('LEMUR_INSTANCE_PROFILE', 'Lemur')), 'blah')

    if service in 'iam':
        return boto.connect_iam(
            aws_access_key_id=role.credentials.access_key,
            aws_secret_access_key=role.credentials.secret_key,
            security_token=role.credentials.session_token)

    elif service in 'elb':
        return boto.ec2.elb.connect_to_region(
            region,
            aws_access_key_id=role.credentials.access_key,
            aws_secret_access_key=role.credentials.secret_key,
            security_token=role.credentials.session_token)

    elif service in 'vpc':
        return boto.connect_vpc(
            aws_access_key_id=role.credentials.access_key,
            aws_secret_access_key=role.credentials.secret_key,
            security_token=role.credentials.session_token)
