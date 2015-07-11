"""
.. module: lemur.destinations.service
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur import database
from lemur.destinations.models import Destination
from lemur.certificates.models import Certificate


def create(label, plugin_name, options, description=None):
    """
    Creates a new destination, that can then be used as a destination for certificates.

    :param label: Destination common name
    :param description:
    :rtype : Destination
    :return: New destination
    """
    destination = Destination(label=label, options=options, plugin_name=plugin_name, description=description)
    return database.create(destination)


def update(destination_id, label, options, description):
    """
    Updates an existing destination.

    :param destination_id:  Lemur assigned ID
    :param destination_number: AWS assigned ID
    :param label: Destination common name
    :param comments:
    :rtype : Destination
    :return:
    """
    destination = get(destination_id)

    destination.label = label
    description.options = options
    destination.description = description

    return database.update(destination)


def delete(destination_id):
    """
    Deletes an destination.

    :param destination_id: Lemur assigned ID
    """
    database.delete(get(destination_id))


def get(destination_id):
    """
    Retrieves an destination by it's lemur assigned ID.

    :param destination_id: Lemur assigned ID
    :rtype : Destination
    :return:
    """
    return database.get(Destination, destination_id)


def get_by_label(label):
    """
    Retrieves a destination by it's label

    :param label:
    :return:
    """
    return database.get(Destination, label, field='label')


def get_all():
    """
    Retrieves all destination currently known by Lemur.

    :return:
    """
    query = database.session_query(Destination)
    return database.find_all(query, Destination, {}).all()


def render(args):
    sort_by = args.pop('sort_by')
    sort_dir = args.pop('sort_dir')
    page = args.pop('page')
    count = args.pop('count')
    filt = args.pop('filter')
    certificate_id = args.pop('certificate_id', None)

    if certificate_id:
        query = database.session_query(Destination).join(Certificate, Destination.certificate)
        query = query.filter(Certificate.id == certificate_id)
    else:
        query = database.session_query(Destination)

    if filt:
        terms = filt.split(';')
        query = database.filter(query, Destination, terms)

    query = database.find_all(query, Destination, args)

    if sort_by and sort_dir:
        query = database.sort(query, Destination, sort_by, sort_dir)

    return database.paginate(query, page, count)

