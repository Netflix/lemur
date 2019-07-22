"""ACME DNS providor for NS1"""
from ns1 import NS1
from flask import current_app


def nsone_api_call():
    """Create NS1 api object"""
    nsone_key = current_app.config.get("ACME_NSONE_KEY", "")
    api = NS1(apiKey=nsone_key)
    return api

def create_txt_record(host, value, account_number):
    """Create a TXT record at the HOST of VALUE"""
    nsone = nsone_api_call()
    try:
        zone = nsone.loadZone(host)
    except Exception as err:
        current_app.logger.error(
            "Failed to load Zone %s: %s" % (host, err)
        )
        return

    try:
        zone.add_TXT(host, value, ttl=300)
        current_app.logger.debug(
            "Creating TXT record {0} with value {1}".format(host, value)
        )
    except Exception as err:
        current_app.logger.error(
            "Failed to add TXT Record to zone %s: %s" % (host, err)
        )
    return 0, 0

def delete_txt_record(change_ids, account_number, host, value):
    """Remove TXT record from HOST of VALUE"""
    nsone = nsone_api_call()
    rec = nsone.loadRecord(host, 'TXT')
    answer_list = rec.data['answers']
    try:
        answer_list.remove(value)
        rec.update(answers=answer_list)
    except Exception as err:
        current_app.logger.debug(
            "Could not find TXT record {0} with value {1}: {2}".format(host, value, err)
        )
        pass
