"""
.. module: lemur.plugins.lemur_aws.elb
    :synopsis: Module contains some often used and helpful classes that
    are used to deal with ELBs

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import botocore
from flask import current_app

from retrying import retry

from lemur.exceptions import InvalidListener
from lemur.plugins.lemur_aws.sts import sts_client, assume_service


def retry_throttled(exception):
    """
    Determiens if this exception is due to throttling
    :param exception:
    :return:
    """
    if isinstance(exception, botocore.exceptions.ClientError):
        if 'Throttling' in exception.message:
            return True
    return False


def is_valid(listener_tuple):
    """
    There are a few rules that aws has when creating listeners,
    this function ensures those rules are met before we try and create
    or update a listener.

    While these could be caught with boto exception handling, I would
    rather be nice and catch these early before we sent them out to aws.
    It also gives us an opportunity to create nice user warnings.

    This validity check should also be checked in the frontend
    but must also be enforced by server.

    :param listener_tuple:
    """
    lb_port, i_port, lb_protocol, arn = listener_tuple
    current_app.logger.debug(lb_protocol)
    if lb_protocol.lower() in ['ssl', 'https']:
        if not arn:
            raise InvalidListener

    return listener_tuple


@sts_client('elb')
@retry(retry_on_exception=retry_throttled, stop_max_attempt_number=7, wait_exponential_multiplier=1000)
def get_elbs(**kwargs):
    """
    Fetches one page elb objects for a given account and region.
    """
    client = kwargs.pop('client')
    return client.describe_load_balancers(**kwargs)


def get_all_elbs(**kwargs):
    """
    Fetches all elbs for a given account/region

    :param kwargs:
    :return:
    """
    elbs = []

    while True:
        response = get_elbs(**kwargs)

        elbs += response['LoadBalancerDescriptions']

        if not response.get('IsTruncated'):
            return elbs

        if response['NextMarker']:
            kwargs.update(dict(marker=response['NextMarker']))


@sts_client('elb')
def describe_load_balancer_policies(load_balancer_name, policy_names, **kwargs):
    """
    Fetching all policies currently associated with an ELB.

    :param load_balancer_name:
    :return:
    """
    return kwargs['client'].describe_load_balancer_policies(LoadBalancerName=load_balancer_name, PolicyNames=policy_names)


@sts_client('elb')
def describe_load_balancer_types(policies, **kwargs):
    """
    Describe the policies with policy details.

    :param policies:
    :return:
    """
    return kwargs['client'].describe_load_balancer_policy_types(PolicyTypeNames=policies)


def attach_certificate(account_number, region, name, port, certificate_id):
    """
    Attaches a certificate to a listener, throws exception
    if certificate specified does not exist in a particular account.

    :param account_number:
    :param region:
    :param name:
    :param port:
    :param certificate_id:
    """
    return assume_service(account_number, 'elb', region).set_lb_listener_SSL_certificate(name, port, certificate_id)


# def create_new_listeners(account_number, region, name, listeners=None):
#     """
#     Creates a new listener and attaches it to the ELB.
#
#     :param account_number:
#     :param region:
#     :param name:
#     :param listeners:
#     :return:
#     """
#     listeners = [is_valid(x) for x in listeners]
#     return assume_service(account_number, 'elb', region).create_load_balancer_listeners(name, listeners=listeners)
#
#
# def update_listeners(account_number, region, name, listeners, ports):
#     """
#     We assume that a listener with a specified port already exists. We can then
#     delete the old listener on the port and create a new one in it's place.
#
#     If however we are replacing a listener e.g. changing a port from 80 to 443 we need
#     to make sure we kept track of which ports we needed to delete so that we don't create
#     two listeners (one 80 and one 443)
#
#     :param account_number:
#     :param region:
#     :param name:
#     :param listeners:
#     :param ports:
#     """
#     # you cannot update a listeners port/protocol instead we remove the only one and
#     # create a new one in it's place
#     listeners = [is_valid(x) for x in listeners]
#
#     assume_service(account_number, 'elb', region).delete_load_balancer_listeners(name, ports)
#     return create_new_listeners(account_number, region, name, listeners=listeners)
#
#
# def delete_listeners(account_number, region, name, ports):
#     """
#     Deletes a listener from an ELB.
#
#     :param account_number:
#     :param region:
#     :param name:
#     :param ports:
#     :return:
#     """
#     return assume_service(account_number, 'elb', region).delete_load_balancer_listeners(name, ports)
#
#
# def get_listeners(account_number, region, name):
#     """
#     Gets the listeners configured on an elb and returns a array of tuples
#
#     :param account_number:
#     :param region:
#     :param name:
#     :return: list of tuples
#     """
#
#     conn = assume_service(account_number, 'elb', region)
#     elbs = conn.get_all_load_balancers(load_balancer_names=[name])
#     if elbs:
#         return elbs[0].listeners
