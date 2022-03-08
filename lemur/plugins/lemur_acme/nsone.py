"""ACME DNS providor for NS1"""
import json
import inspect
import time
import requests

from flask import current_app
from sentry_sdk import capture_exception
from lemur.common import utils
import lemur.dns_providers.util as dnsutil
from lemur.extensions import metrics

REQUIRED_VARIABLES = [
    "ACME_NSONE_KEY",
]


def get_zones():
    """
    Retrieve authoritative zones from the NS1 API and return a list of zones

    :raise: Exception
    :return: list of Zone Objects
    """
    _check_conf()
    path = f'{"/v1/zones"}'
    zones = []
    function = inspect.currentframe().f_code.co_name
    log_data = {
        "function": function
    }
    try:
        records = _get(path)
        log_data["message"] = "Retrieved Zones Successfully"
        current_app.logger.debug(log_data)
    except Exception as err:
        capture_exception()
        log_data["message"] = "Failed to Retrieve Zone Data"
        log_data["error"] = err
        current_app.logger.debug(log_data)
        raise
    for record in records:
        zone = record['zone']
        if record['primary']['enabled']:
            zones.append(zone)
    return zones


def create_txt_record(domain, token, account_number=None):
    """
    Create a TXT record for the given domain and token and return a change_id tuple

    :param domain: FQDN
    :param token: challenge value
    :param account_number:
    :return: tuple of domain/token
    """
    _check_conf()

    function = inspect.currentframe().f_code.co_name
    log_data = {
        "function": function,
        "fqdn": domain,
        "token": token,
        "account": account_number,
    }
    # Create new record
    answer = {"answer": [token]}
    # Get current records
    found = False
    records = _get_txt_records(domain)
    for each in records['answers']:
        if token in each['answer']:
            found = True
            break
    if not found:
        records['answers'].append(answer)
    log_data["records"] = records
    try:
        if 'id' in records:
            _patch_txt_records(domain, records)
        else:
            _patch_txt_records(domain, records, patch=False)
        log_data["message"] = "TXT record(s) successfully created"
        current_app.logger.debug(log_data)
    except Exception as err:
        capture_exception()
        log_data["Exception"] = err
        log_data["message"] = "Unable to create TXT record(s)"
        current_app.logger.debug(log_data)
    change_id = (domain, token)
    return change_id


def wait_for_dns_change(change_id, account_number=None):
    """
    Checks the authoritative DNS Server to see if changes have propagated.

    :param change_id: tuple of domain/token
    :param account_number:
    :return:
    """
    _check_conf()
    domain, token = change_id
    number_of_attempts = 3
    zone = _get_zone_name(domain)
    nameserver = dnsutil.get_authoritative_nameserver(zone)
    record_found = False
    attempts = 0
    while attempts < number_of_attempts:
        txt_records = dnsutil.get_dns_records(domain, "TXT", nameserver)
        for txt_record in txt_records:
            if txt_record == token:
                record_found = True
                break
        if record_found:
            break
        time.sleep(5)
        attempts += 1
    function = inspect.currentframe().f_code.co_name
    log_data = {
        "function": function,
        "fqdn": domain,
        "status": record_found,
        "account": account_number,
        "message": "Record status on NS1 authoritative server",
    }
    current_app.logger.debug(log_data)
    if record_found:
        metrics.send(
            f"{function}.success",
            "counter", 1,
            metric_tags={"fqdn": domain, "txt_record": token}
        )
    else:
        metrics.send(
            f"{function}.fail",
            "counter", 1,
            metric_tags={"fqdn": domain, "txt_record": token}
        )


def delete_txt_record(change_id, account_number, domain, token):
    """
    Delete the TXT record for the given domain and token

    :param change_id: tuple of domain/token
    :param account_number:
    :param domain: FQDN
    :param token: challenge to delete
    :return:
    """
    _check_conf()
    function = inspect.currentframe().f_code.co_name
    log_data = {
        "function": function,
        "fqdn": domain,
        "token": token,
        "change": change_id,
        "account": account_number,
    }
    zone = _get_zone_name(domain)
    records = _get_txt_records(domain)
    found = False
    for each in records['answers']:
        if token in each['answer']:
            found = True
            each['answer'].remove(token)
            if len(each['answer']) == 0:
                try:
                    path = f"/v1/zones/{zone}/{domain}/TXT"
                    _delete(path)
                    log_data["message"] = "TXT record successfully deleted"
                    current_app.logger.debug(log_data)
                except Exception as err:
                    capture_exception()
                    log_data["Exception"] = err
                    log_data["message"] = "Unable to delete TXT record"
                    current_app.logger.debug(log_data)
            else:
                try:
                    _patch_txt_records(domain, records)
                    log_data["message"] = "TXT record successfully deleted"
                    current_app.logger.debug(log_data)
                except Exception as err:
                    capture_exception()
                    log_data["Exception"] = err
                    log_data["message"] = "Unable to delete TXT record"
                    current_app.logger.debug(log_data)
    # Since the matching token is not in DNS, there is nothing to delete
    if not found:
        log_data["message"] = "Unable to delete TXT record: Token not found in existing TXT records"
        current_app.logger.debug(log_data)
        return


def _check_conf():
    """
    Verifies required configuration variables are set

    :return:
    """
    utils.validate_conf(current_app, REQUIRED_VARIABLES)


def _generate_header():
    """
    Generate a NS1 API header and return it as a dictionary

    :return: Dict of header parameters
    """
    api_key = current_app.config.get("ACME_NSONE_KEY")
    headers = {'X-NSONE-Key': api_key}
    return headers


def _get_zone_name(domain):
    """
    Get most specific matching zone for the given domain and return as a String

    :param domain: FQDN
    :return: FQDN of domain
    """
    zones = get_zones()
    zone_name = ""
    for zone in zones:
        if domain.endswith("." + zone) or domain == zone:
            if zone.count(".") > zone_name.count("."):
                zone_name = zone
    if not zone_name:
        function = inspect.currentframe().f_code.co_name
        log_data = {
            "function": function,
            "fqdn": domain,
            "message": "No NS1 zone name found.",
        }
        current_app.logger.debug(log_data)
        metrics.send(f"{function}.fail", "counter", 1)
    return zone_name


def _get_txt_records(domain):
    """
    Retrieve TXT records for a given domain and return list of Record Objects

    :param domain: FQDN
    :return: list of Record objects
    """
    zone = _get_zone_name(domain)
    path = f"/v1/zones/{zone}/{domain}/TXT"

    function = inspect.currentframe().f_code.co_name
    log_data = {
        "function": function
    }
    try:
        records = _get(path)
        log_data["message"] = "Retrieved TXT Records Successfully"
        log_data['records'] = records
        current_app.logger.debug(log_data)

    except Exception as err:
        capture_exception()
        log_data["Exception"] = err
        log_data["message"] = "Failed to Retrieve TXT Records"
        current_app.logger.debug(log_data)
        records = {}
        records['domain'] = domain
        records['zone'] = zone
        records['type'] = 'TXT'
        records['answers'] = []

    return records


def _get(path, params=None):
    """
    Execute a GET request on the given URL (base_uri + path) and return response as JSON object

    :param path: Relative URL path
    :param params: additional parameters
    :return: json response
    """
    base_uri = 'https://api.nsone.net'
    resp = requests.get(
        f"{base_uri}{path}",
        headers=_generate_header(),
        params=params,
        verify=True
    )
    resp.raise_for_status()
    return resp.json()


def _patch_txt_records(domain, records, patch=True):
    """
    Send Patch or Put request to NS1 Server

    :param domain: FQDN
    :param account_number:
    :param records: List of Record objects
    :return:
    """
    # Create Txt Records
    zone = _get_zone_name(domain)
    path = f"/v1/zones/{zone}/{domain}/TXT"
    if patch:
        _patch(path, records)
    else:
        _put(path, records)


def _patch(path, payload):
    """
    Execute a Patch to update the given URL (base_uri + path) with given payload

    :param path:
    :param payload:
    :return:
    """
    base_uri = 'https://api.nsone.net'
    resp = requests.post(
        f"{base_uri}{path}",
        data=json.dumps(payload),
        headers=_generate_header(),
        verify=True
    )
    resp.raise_for_status()


def _put(path, payload):
    """
    Execute a Put to add the given URL (base_uri + path) with payload

    :param path:
    :param payload:
    :return:
    """
    base_uri = 'https://api.nsone.net'
    resp = requests.put(
        f"{base_uri}{path}",
        data=json.dumps(payload),
        headers=_generate_header(),
        verify=True
    )
    resp.raise_for_status()


def _delete(path):
    """
    Execute a Delete requests on the given URL (base_uri + path)

    """
    base_uri = 'https://api.nsone.net'
    resp = requests.delete(
        f"{base_uri}{path}",
        headers=_generate_header(),
        verify=True
    )
    resp.raise_for_status()
