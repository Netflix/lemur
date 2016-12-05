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
from lemur.plugins.lemur_aws.sts import sts_client


def retry_throttled(exception):
    """
    Determiens if this exception is due to throttling
    :param exception:
    :return:
    """
    if isinstance(exception, botocore.exceptions.ClientError):
        if exception.response['Error']['Code'] == 'LoadBalancerNotFound':
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


@sts_client('elb')
@retry(retry_on_exception=retry_throttled, stop_max_attempt_number=7, wait_exponential_multiplier=1000)
def attach_certificate(name, port, certificate_id, **kwargs):
    """
    Attaches a certificate to a listener, throws exception
    if certificate specified does not exist in a particular account.

    :param name:
    :param port:
    :param certificate_id:
    """
    try:
        return kwargs['client'].set_load_balancer_listener_ssl_certificate(LoadBalancerName=name, LoadBalancerPort=port, SSLCertificateId=certificate_id)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'LoadBalancerNotFound':
            current_app.logger.warning("Loadbalancer does not exist.")
        else:
            raise e
