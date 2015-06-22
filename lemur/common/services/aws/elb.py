"""
.. module:: elb
    :synopsis: Module contains some often used and helpful classes that
    are used to deal with ELBs

.. moduleauthor:: Kevin Glisson (kglisson@netflix.com)
"""
import boto.ec2

from flask import current_app

from lemur.exceptions import InvalidListener
from lemur.common.services.aws.sts import assume_service


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

    current_app.logger.debug(listener_tuple)
    lb_port, i_port, lb_protocol, arn = listener_tuple
    current_app.logger.debug(lb_protocol)
    if lb_protocol.lower() in ['ssl', 'https']:
        if not arn:
            raise InvalidListener

    return listener_tuple

def get_all_regions():
    """
    Retrieves all current EC2 regions.

    :return:
    """
    regions = []
    for r in boto.ec2.regions():
        regions.append(r.name)
    return regions

def get_all_elbs(account_number, region):
    """
    Fetches all elb objects for a given account and region.

    :param account_number:
    :param region:
    """
    marker = None
    elbs = []
    return assume_service(account_number, 'elb', region).get_all_load_balancers()
# TODO create pull request for boto to include elb marker support
#    while True:
#        app.logger.debug(response.__dict__)
#        raise Exception
#        result = response['list_server_certificates_response']['list_server_certificates_result']
#
#        for elb in result['server_certificate_metadata_list']:
#            elbs.append(elb)
#
#        if result['is_truncated'] == 'true':
#            marker = result['marker']
#        else:
#            return elbs



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


def create_new_listeners(account_number, region, name, listeners=None):
    """
    Creates a new listener and attaches it to the ELB.

    :param account_number:
    :param region:
    :param name:
    :param listeners:
    :return:
    """
    listeners = [is_valid(x) for x in listeners]
    return assume_service(account_number, 'elb', region).create_load_balancer_listeners(name, listeners=listeners)


def update_listeners(account_number, region, name, listeners, ports):
    """
    We assume that a listener with a specified port already exists. We can then
    delete the old listener on the port and create a new one in it's place.

    If however we are replacing a listener e.g. changing a port from 80 to 443 we need
    to make sure we kept track of which ports we needed to delete so that we don't create
    two listeners (one 80 and one 443)

    :param account_number:
    :param region:
    :param name:
    :param listeners:
    :param ports:
    """
    # you cannot update a listeners port/protocol instead we remove the only one and
    # create a new one in it's place
    listeners = [is_valid(x) for x in listeners]

    assume_service(account_number, 'elb', region).delete_load_balancer_listeners(name, ports)
    return create_new_listeners(account_number, region, name, listeners=listeners)


def delete_listeners(account_number, region, name, ports):
    """
    Deletes a listener from an ELB.

    :param account_number:
    :param region:
    :param name:
    :param ports:
    :return:
    """
    return assume_service(account_number, 'elb', region).delete_load_balancer_listeners(name, ports)

