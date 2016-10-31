"""
.. module: lemur.common.services.aws.sts
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


def construct_role_arn(role_type='role', **kwargs):
    account_number = kwargs.get('account_number') or \
        current_app.config.get('AWS_DEFAULT_ACCOUNT_NUMBER') or \
        boto3.client('sts').get_caller_identity().get('Account')
    arn_data = {
        'num': account_number,
        'role_type': role_type,
        'name': current_app.config.get('LEMUR_INSTANCE_PROFILE', 'Lemur')
    }
    arn_data['service'] = 'sts' if role_type == 'assumed-role' else 'iam'

    return 'arn:aws:{service}::{num}:{role_type}/{name}'.format(**arn_data)


def already_assumed_target_role(**kwargs):
    target_arn = construct_role_arn('assumed-role', **kwargs)
    current_arn = boto3.client('sts').get_caller_identity().get('Arn')
    return current_arn.startswith(target_arn)


def _current_session_region():
    _s = boto3._get_default_session()
    return _s.region_name


def _current_session_credentials_dict():
    _c = boto3._get_default_session().get_credentials()
    return {
        'AccessKeyId': _c.access_key,
        'SecretAccessKey': _c.secret_key,
        'SessionToken': _c.token
    }


def sts_client(service, service_type='client'):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            sts = boto3.client('sts')

            region_name = kwargs.get('region') or _current_session_region()
            role = None

            if already_assumed_target_role(**kwargs):
                role = {'Credentials': _current_session_credentials_dict()}
            else:
                role = sts.assume_role(
                    RoleArn=construct_role_arn(**kwargs),
                    # TODO add user specific information to RoleSessionName
                    RoleSessionName='lemur'
                )

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
