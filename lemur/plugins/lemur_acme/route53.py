import time
from functools import wraps

from flask import current_app

import boto3


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
                    region_name=kwargs.pop('region'),
                    aws_access_key_id=role['Credentials']['AccessKeyId'],
                    aws_secret_access_key=role['Credentials']['SecretAccessKey'],
                    aws_session_token=role['Credentials']['SessionToken']
                )
                kwargs['client'] = client
            elif service_type == 'resource':
                resource = boto3.resource(
                    service,
                    region_name=kwargs.pop('region'),
                    aws_access_key_id=role['Credentials']['AccessKeyId'],
                    aws_secret_access_key=role['Credentials']['SecretAccessKey'],
                    aws_session_token=role['Credentials']['SessionToken']
                )
                kwargs['resource'] = resource
            return f(*args, **kwargs)

        return decorated_function

    return decorator


@sts_client('route53')
def wait_for_r53_change(change_id, client=None):
    _, change_id = change_id

    while True:
        response = client.get_change(Id=change_id)
        if response["ChangeInfo"]["Status"] == "INSYNC":
            return
        time.sleep(5)


@sts_client('route53')
def find_zone_id(domain, client=None):
    paginator = client.get_paginator("list_hosted_zones")
    zones = []
    for page in paginator.paginate():
        for zone in page["HostedZones"]:
            if domain.endswith(zone["Name"]) or (domain + ".").endswith(zone["Name"]):
                if not zone["Config"]["PrivateZone"]:
                    zones.append((zone["Name"], zone["Id"]))

    if not zones:
        raise ValueError(
            "Unable to find a Route53 hosted zone for {}".format(domain)
        )


@sts_client('route53')
def change_txt_record(action, zone_id, domain, value, client=None):
    response = client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": domain,
                        "Type": "TXT",
                        "TTL": 300,
                        "ResourceRecords": [
                            # For some reason TXT records need to be
                            # manually quoted.
                            {"Value": '"{}"'.format(value)}
                        ],
                    }
                }
            ]
        }
    )
    return response["ChangeInfo"]["Id"]


def create_txt_record(host, value):
    zone_id = find_zone_id(host)
    change_id = change_txt_record(
        "CREATE",
        zone_id,
        host,
        value,
    )
    return zone_id, change_id


def delete_txt_record(change_id, host, value):
    zone_id, _ = change_id
    change_txt_record(
        "DELETE",
        zone_id,
        host,
        value
    )


@sts_client('route53')
def wait_for_change(change_id, client=None):
    _, change_id = change_id

    while True:
        response = client.get_change(Id=change_id)
        if response["ChangeInfo"]["Status"] == "INSYNC":
            return
        time.sleep(5)
