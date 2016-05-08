"""
.. module: lemur.common.services.aws.sts
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import boto
import boto.ec2.elb
import os
from flask import current_app


class Credentials(object):
    access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    session_token = None


class Role(object):
    credentials = Credentials()


def assume_service(account_number, service, region=None):
    try:
        conn = boto.connect_sts()
        role = conn.assume_role('arn:aws:iam::{0}:role/{1}'.format(
            account_number, current_app.config.get('LEMUR_INSTANCE_PROFILE', 'Lemur')), 'blah')
    except:
        current_app.logger.warn('Could not connect to STS, reading credentials from environment')
        role = Role()
        pass

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

    elif service in 's3':
        return boto.s3.connect_to_region(
            region,
            aws_access_key_id=role.credentials.access_key,
            aws_secret_access_key=role.credentials.secret_key,
            security_token=role.credentials.session_token)
