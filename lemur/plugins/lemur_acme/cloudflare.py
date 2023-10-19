import time

import CloudFlare
from flask import current_app


def cf_api_call():
    cf_key = current_app.config.get("ACME_CLOUDFLARE_KEY", "")
    cf_email = current_app.config.get("ACME_CLOUDFLARE_EMAIL", "")
    return CloudFlare.CloudFlare(email=cf_email, token=cf_key)


def find_zone_id(host):
    elements = host.split(".")
    cf = cf_api_call()

    n = 1

    while n < 5:
        n = n + 1
        domain = ".".join(elements[-n:])
        current_app.logger.debug(f"Trying to get ID for zone {domain}")

        try:
            zone = cf.zones.get(params={"name": domain, "per_page": 1})
        except Exception as e:
            current_app.logger.error("Cloudflare API error: %s" % e)
            pass

        if len(zone) == 1:
            break

    if len(zone) == 0:
        current_app.logger.error("No zone found")
        return
    else:
        return zone[0]["id"]


def wait_for_dns_change(change_id, account_number=None):
    cf = cf_api_call()
    zone_id, record_id = change_id
    while True:
        r = cf.zones.get(zone_id, record_id)
        current_app.logger.debug("Record status: %s" % r["status"])
        if r["status"] == "active":
            break
        time.sleep(1)
    return


def create_txt_record(host, value, account_number):
    cf = cf_api_call()
    zone_id = find_zone_id(host)
    if not zone_id:
        return

    txt_record = {"name": host, "type": "TXT", "content": value}

    current_app.logger.debug(
        f"Creating TXT record {host} with value {value}"
    )

    try:
        r = cf.zones.dns_records.post(zone_id, data=txt_record)
    except Exception as e:
        current_app.logger.error(
            "/zones.dns_records.post {}: {}".format(txt_record["name"], e)
        )
    return zone_id, r["id"]


def delete_txt_record(change_ids, account_number, host, value):
    cf = cf_api_call()
    for change_id in change_ids:
        zone_id, record_id = change_id
        current_app.logger.debug(f"Removing record with id {record_id}")
        try:
            cf.zones.dns_records.delete(zone_id, record_id)
        except Exception as e:
            current_app.logger.error("/zones.dns_records.post: %s" % e)
