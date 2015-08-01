"""
.. module: lemur.sources.service
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur import database
from lemur.sources.models import Source
from lemur.certificates.models import Certificate


def create(label, plugin_name, options, description=None):
    """
    Creates a new source, that can then be used as a source for certificates.

    :param label: Source common name
    :param description:
    :rtype : Source
    :return: New source
    """
    source = Source(label=label, options=options, plugin_name=plugin_name, description=description)
    return database.create(source)


def update(source_id, label, options, description):
    """
    Updates an existing source.

    :param source_id:  Lemur assigned ID
    :param label: Source common name
    :rtype : Source
    :return:
    """
    source = get(source_id)

    source.label = label
    source.options = options
    source.description = description

    return database.update(source)


def delete(source_id):
    """
    Deletes an source.

    :param source_id: Lemur assigned ID
    """
    database.delete(get(source_id))


def get(source_id):
    """
    Retrieves an source by it's lemur assigned ID.

    :param source_id: Lemur assigned ID
    :rtype : Source
    :return:
    """
    return database.get(Source, source_id)


def get_by_label(label):
    """
    Retrieves a source by it's label

    :param label:
    :return:
    """
    return database.get(Source, label, field='label')


def get_all():
    """
    Retrieves all source currently known by Lemur.

    :return:
    """
    query = database.session_query(Source)
    return database.find_all(query, Source, {}).all()


def render(args):
    sort_by = args.pop('sort_by')
    sort_dir = args.pop('sort_dir')
    page = args.pop('page')
    count = args.pop('count')
    filt = args.pop('filter')
    certificate_id = args.pop('certificate_id', None)

    if certificate_id:
        query = database.session_query(Source).join(Certificate, Source.certificate)
        query = query.filter(Certificate.id == certificate_id)
    else:
        query = database.session_query(Source)

    if filt:
        terms = filt.split(';')
        query = database.filter(query, Source, terms)

    query = database.find_all(query, Source, args)

    if sort_by and sort_dir:
        query = database.sort(query, Source, sort_by, sort_dir)

    return database.paginate(query, page, count)
