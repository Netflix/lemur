import time

from lemur.plugins.lemur_aws.sts import sts_client


@sts_client("route53")
def wait_for_dns_change(change_id, client=None):
    _, change_id = change_id

    while True:
        response = client.get_change(Id=change_id)
        if response["ChangeInfo"]["Status"] == "INSYNC":
            return
        time.sleep(5)


@sts_client("route53")
def find_zone_id(domain, client=None):
    return _find_zone_id(domain, client)


def _find_zone_id(domain, client=None):
    paginator = client.get_paginator("list_hosted_zones")
    min_diff_length = float("inf")
    chosen_zone = None

    for page in paginator.paginate():
        for zone in page["HostedZones"]:
            # strip the trailing "." to match against the domain (but return the full, original value)
            zone_name = zone["Name"].rstrip(".")
            if domain == zone_name or domain.endswith("." + zone_name):
                if not zone["Config"]["PrivateZone"]:
                    diff_length = len(domain) - len(zone_name)
                    if diff_length < min_diff_length:
                        min_diff_length = diff_length
                        chosen_zone = (zone["Name"], zone["Id"])

    if chosen_zone is None:
        raise ValueError(f"Unable to find a Route53 hosted zone for {domain}")

    return chosen_zone[1]  # Return the chosen zone ID


@sts_client("route53")
def get_zones(client=None):
    paginator = client.get_paginator("list_hosted_zones")
    zones = []
    for page in paginator.paginate():
        for zone in page["HostedZones"]:
            if not zone["Config"]["PrivateZone"]:
                zones.append(
                    zone["Name"][:-1]
                )  # We need [:-1] to strip out the trailing dot.
    return zones


@sts_client("route53")
def change_txt_record(action, zone_id, domain, value, client=None):
    current_txt_records = []
    try:
        current_records = client.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordName=domain,
            StartRecordType="TXT",
            MaxItems="1",
        )["ResourceRecordSets"]

        for record in current_records:
            if record.get("Type") == "TXT":
                current_txt_records.extend(record.get("ResourceRecords", []))
    except Exception as e:
        # Current Resource Record does not exist
        if "NoSuchHostedZone" not in str(type(e)):
            raise
    # For some reason TXT records need to be
    # manually quoted.
    seen = False
    for record in current_txt_records:
        for k, v in record.items():
            if f'"{value}"' == v:
                seen = True
    if not seen:
        current_txt_records.append({"Value": f'"{value}"'})

    if action == "DELETE" and len(current_txt_records) > 1:
        # If we want to delete one record out of many, we'll update the record to not include the deleted value instead.
        # This allows us to support concurrent issuance.
        current_txt_records = [
            record
            for record in current_txt_records
            if not (record.get("Value") == f'"{value}"')
        ]
        action = "UPSERT"

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
                        "ResourceRecords": current_txt_records,
                    },
                }
            ]
        },
    )
    return response["ChangeInfo"]["Id"]


def create_txt_record(host, value, account_number):
    zone_id = find_zone_id(host, account_number=account_number)
    change_id = change_txt_record(
        "UPSERT", zone_id, host, value, account_number=account_number
    )

    return zone_id, change_id


def delete_txt_record(change_ids, account_number, host, value):
    for change_id in change_ids:
        zone_id, _ = change_id
        try:
            change_txt_record(
                "DELETE", zone_id, host, value, account_number=account_number
            )
        except Exception as e:
            if "but it was not found" in e.response.get("Error", {}).get("Message"):
                # We tried to delete a record that doesn't exist. We'll ignore this error.
                pass
            else:
                raise
