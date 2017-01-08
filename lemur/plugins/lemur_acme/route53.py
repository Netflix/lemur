import time
from lemur.plugins.lemur_aws.sts import sts_client


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


def create_txt_record(account_number, host, value):
    zone_id = find_zone_id(host, account_number=account_number)
    change_id = change_txt_record(
        "CREATE",
        zone_id,
        host,
        value,
        account_number=account_number
    )
    return zone_id, change_id


def delete_txt_record(change_id, account_number, host, value):
    zone_id, _ = change_id
    change_txt_record(
        "DELETE",
        zone_id,
        host,
        value,
        account_number=account_number
    )
