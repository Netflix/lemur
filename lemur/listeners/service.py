"""
.. module: lemur.listeners.service
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from sqlalchemy import func

from lemur import database

from lemur.exceptions import CertificateUnavailable

from lemur.elbs.models import ELB
from lemur.listeners.models import Listener
from lemur.elbs import service as elb_service
from lemur.certificates import service as certificate_service

# from lemur.common.services.aws.elb import update_listeners, create_new_listeners, delete_listeners


def verify_attachment(certificate_id, elb_account_number):
    """
    Ensures that the certificate we want ot attach to our listener is
    in the same account as our listener.

    :rtype : Certificate
    :param certificate_id:
    :param elb_account_number:
    :return: :raise CertificateUnavailable:
    """
    cert = certificate_service.get(certificate_id)

    # we need to ensure that the specified cert is in our account
    for account in cert.accounts:
        if account.account_number == elb_account_number:
            break
    else:
        raise CertificateUnavailable
    return cert


def get(listener_id):
    return database.get(Listener, listener_id)


def create(elb_id, instance_protocol, instance_port, load_balancer_port, load_balancer_protocol, certificate_id=None):
    listener = Listener(elb_id,
                        instance_port,
                        instance_protocol,
                        load_balancer_port,
                        load_balancer_protocol
               )

    elb = elb_service.get(elb_id)
    elb.listeners.append(listener)
    account_number = elb.account.account_number

    cert = verify_attachment(certificate_id, account_number)
    listener_tuple = (load_balancer_port, instance_port, load_balancer_protocol, cert.get_art(account_number),)
    # create_new_listeners(account_number, elb.region, elb.name, [listener_tuple])

    return {'message': 'Listener has been created'}


def update(listener_id, **kwargs):
    listener = get(listener_id)

    # if the lb_port has changed we need to make sure we are deleting
    # the listener on the old port to avoid listener duplication
    ports = []
    if listener.load_balancer_port != kwargs.get('load_balancer_port'):
        ports.append(listener.load_balancer_port)
    else:
        ports.append(kwargs.get('load_balancer_port'))

    certificate_id = kwargs.get('certificate_id')

    listener.instance_port = kwargs.get('instance_port')
    listener.instance_protocol = kwargs.get('instance_protocol')
    listener.load_balancer_port = kwargs.get('load_balancer_port')
    listener.load_balancer_protocol = kwargs.get('load_balancer_protocol')

    elb = listener.elb
    account_number = listener.elb.account.account_number

    arn = None
    if certificate_id:
        cert = verify_attachment(certificate_id, account_number)
        cert.elb_listeners.append(listener)
        arn = cert.get_arn(account_number)

    # remove certificate that is no longer wanted
    if listener.certificate and not certificate_id:
        listener.certificate.remove()

    database.update(listener)
    listener_tuple = (listener.load_balancer_port, listener.instance_port, listener.load_balancer_protocol, arn,)
    # update_listeners(account_number, elb.region, elb.name, [listener_tuple], ports)

    return {'message': 'Listener has been updated'}


def delete(listener_id):
    # first try to delete the listener in aws
    listener = get(listener_id)
    # delete_listeners(listener.elb.account.account_number, listener.elb.region, listener.elb.name, [listener.load_balancer_port])
    # cleanup operation in lemur
    database.delete(listener)


def render(args):
    query = database.session_query(Listener)

    sort_by = args.pop('sort_by')
    sort_dir = args.pop('sort_dir')
    page = args.pop('page')
    count = args.pop('count')
    filt = args.pop('filter')
    certificate_id = args.pop('certificate_id', None)
    elb_id = args.pop('elb_id', None)

    if certificate_id:
        query = database.get_all(Listener, certificate_id, field='certificate_id')

    if elb_id:
        query = query.filter(Listener.elb_id == elb_id)

    if filt:
        terms = filt.split(';')
        query = database.filter(query, Listener, terms)

    query = database.find_all(query, Listener, args)

    if sort_by and sort_dir:
        query = database.sort(query, Listener, sort_by, sort_dir)

    return database.paginate(query, page, count)


def stats(**kwargs):
    attr = getattr(Listener, kwargs.get('metric'))
    query = database.db.session.query(attr, func.count(attr))
    query = query.join(Listener.elb)

    if kwargs.get('account_id'):
        query = query.filter(ELB.account_id == kwargs.get('account_id'))

    if kwargs.get('active') == 'true':
        query = query.filter(Listener.certificate_id != None)  # noqa

    items = query.group_by(attr).all()
    results = []
    for key, count in items:
        if key:
            results.append({"key": key, "y": count})
    return results
