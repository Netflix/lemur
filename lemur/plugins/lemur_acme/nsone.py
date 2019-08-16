"""ACME DNS providor for NS1"""
from time import sleep
import ns1
from flask import current_app

def nsone_api_call():
    """Create NS1 api object"""
    nsone_key = current_app.config.get("ACME_NSONE_KEY", "")
    try:
        api = ns1.NS1(apiKey=nsone_key)
    except ns1.rest.errors.AuthException:
        current_app.logger.error(
            'NS1 Authentication Failure'
        )
    return api

def get_zone(host):
    """Find the parent domain/zone for the given host"""
    try:
        zone = host.split('.')[-2]+'.'+host.split('.')[-1]
    except IndexError:
        zone = host
        current_app.logger.error(
            'Failed to find the zone for host: {}'.format(host)
        )
    return zone

def add_answer(answers, value):
    """Add a value to the answers list"""
    if answers:
        for each in answers:
            if 'answer' in each:
                if not value in each['answer']:
                    each['answer'].append(value)
    else:
        answers = [{'answer': [value]}]
    return answers

def wait_for_dns_change(change_id, account_number=None):
    """Wait for DNS to update, short circuit on token 0"""
    fqdn, token = change_id
    current_app.logger.debug(
        "wait_for_dns_change: params: {}, {}, {}".format(fqdn, token, account_number)
    )
    if token == 0:
        return 1
    nsone = nsone_api_call()
    zone_name = get_zone(fqdn)
    try:
        zone = nsone.loadZone(zone_name)
    except ns1.rest.errors.ResourceException:
        current_app.logger.error(
            "wait_for_dns_change: cound not load zone {}".format(zone_name)
        )
    while True:
        try:
            rec = zone.loadRecord(fqdn, 'TXT')
            if rec.data['id'] == token:
                current_app.logger.debug(
                    "wait_for_dns_change: found dns record for {}: {}: {}".format(
                        fqdn, token, rec.data
                    )
                )
                return
        except AttributeError:
            current_app.logger.debug(
                "wait_for_dns_change: No ID in record from NS1 for {}".format(fqdn)
            )
        except ns1.rest.errors.ResourceException:
            current_app.logger.debug(
                "wait_for_dns_change: Record not found {}: {}".format(fqdn, token)
            )
        sleep(1)

def create_txt_record(host, value, account_number):
    """Create a TXT record at the host of given value"""
    current_app.logger.debug(
        "create_txt_record: params: {}, {}, {}".format(host, value, account_number)
    )
    nsone = nsone_api_call()
    token = 0
    zone_name = get_zone(host)
    try:
        zone = nsone.loadZone(zone_name)
    except ns1.rest.errors.ResourceException:
        current_app.logger.error(
            "Failed to load Zone {}".format(zone_name)
        )
        return host, token
    try:
        rec = zone.add_TXT(host, value, ttl=300)
        try:
            token = rec.data['id']
            current_app.logger.debug(
                "create TXT record: {0} with value {1}".format(host, value)
            )
        except AttributeError:
            current_app.logger.error("create TXT record: no token on add")
    except ns1.rest.errors.ResourceException:
        current_app.logger.debug(
            "create TXT record: record exists for {}: {}.".format(host, value)
        )
        try:
            rec = zone.loadRecord(host, 'TXT')
            try:
                token = rec.data['id']
            except AttributeError:
                current_app.logger.error("no token on update")
        except ns1.rest.errors.ResourceException:
            current_app.logger.error(
                "create TXT record: critical: failed to add or load record {}".format(host)
            )
    return host, token

def delete_txt_record(change_ids, account_number, host, value):
    """Remove TXT record from HOST of VALUE"""
    nsone = nsone_api_call()
    current_app.logger.debug(
        "delete TXT record: for {2}: of {3}; {0}:{1} ".format(
            change_ids, account_number, host, value
        )
    )
    if not host:
        current_app.logger.debug(
            "delete TXT record: no host passed"
        )
        return
    acme_challenge_string = "_acme-challenge"
    if not host.startswith(acme_challenge_string):
        current_app.logger.debug(
            "delete TXT record: Domain {} doesn't start with string {}. "
            "Cowardly refusing to delete TXT record".format(
                host, acme_challenge_string
            )
        )
        return
    zone = nsone.loadZone(get_zone(host))
    try:
        rec = zone.loadRecord(host, "TXT")
        rec.delete()
    except ns1.rest.errors.ResourceException:
        current_app.logger.error(
            'delete TXT record: ns1 error, record not found {}'.format(host)
        )
    return
