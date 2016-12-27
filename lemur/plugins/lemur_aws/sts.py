"""
.. module: lemur.plugins.lemur_aws.sts
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from functools import wraps

import boto
import boto.ec2.elb
import boto3

from flask import current_app


def assume_service(account_number, service, region='us-east-1'):
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

    elif service in 's3':
        return boto.s3.connect_to_region(
            region,
            aws_access_key_id=role.credentials.access_key,
            aws_secret_access_key=role.credentials.secret_key,
            security_token=role.credentials.session_token)


def sts_client(service, service_type='client'):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            sts = boto3.client('sts')
            arn = 'arn:aws:iam::{0}:role/{1}'.format(
                kwargs.pop('account_number'),
                current_app.config.get('LEMUR_INSTANCE_PROFILE', 'Lemur')
            )

            # TODO add user specific information to RoleSessionName
            role = sts.assume_role(RoleArn=arn, RoleSessionName='lemur')

            if service_type == 'client':
                client = boto3.client(
                    service,
                    region_name=kwargs.pop('region', 'us-east-1'),
                    aws_access_key_id=role['Credentials']['AccessKeyId'],
                    aws_secret_access_key=role['Credentials']['SecretAccessKey'],
                    aws_session_token=role['Credentials']['SessionToken']
                )
                kwargs['client'] = client
            elif service_type == 'resource':
                resource = boto3.resource(
                    service,
                    region_name=kwargs.pop('region', 'us-east-1'),
                    aws_access_key_id=role['Credentials']['AccessKeyId'],
                    aws_secret_access_key=role['Credentials']['SecretAccessKey'],
                    aws_session_token=role['Credentials']['SessionToken']
                )
                kwargs['resource'] = resource
            return f(*args, **kwargs)

        return decorated_function

    return decorator
