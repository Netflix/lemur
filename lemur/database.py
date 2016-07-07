"""
.. module: lemur.database
    :platform: Unix
    :synopsis: This module contains all of the database related methods
    needed for lemur to interact with a datastore

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy import exc
from sqlalchemy.sql import and_, or_
from sqlalchemy.orm import make_transient

from lemur.extensions import db
from lemur.exceptions import AttrNotFound, DuplicateError


def filter_none(kwargs):
    """
    Remove all `None` values froma  given dict. SQLAlchemy does not
    like to have values that are None passed to it.

    :param kwargs: Dict to filter
    :return: Dict without any 'None' values
    """
    n_kwargs = {}
    for k, v in kwargs.items():
        if v:
            n_kwargs[k] = v
    return n_kwargs


def session_query(model):
    """
    Returns a SQLAlchemy query object for the specified `model`.

    If `model` has a ``query`` attribute already, that object will be returned.
    Otherwise a query will be created and returned based on `session`.

    :param model: sqlalchemy model
    :return: query object for model
    """
    return model.query if hasattr(model, 'query') else db.session.query(model)


def create_query(model, kwargs):
    """
    Returns a SQLAlchemy query object for specified `model`. Model
    filtered by the kwargs passed.

    :param model:
    :param kwargs:
    :return:
    """
    s = session_query(model)
    return s.filter_by(**kwargs)


def commit():
    """
    Helper to commit the current session.
    """
    db.session.commit()


def add(model):
    """
    Helper to add a `model` to the current session.

    :param model:
    :return:
    """
    db.session.add(model)


def find_all(query, model, kwargs):
    """
    Returns a query object that ensures that all kwargs
    are present.

    :param query:
    :param model:
    :param kwargs:
    :return:
    """
    conditions = []
    kwargs = filter_none(kwargs)
    for attr, value in kwargs.items():
        if not isinstance(value, list):
            value = value.split(',')

        conditions.append(getattr(model, attr).in_(value))

    return query.filter(and_(*conditions))


def find_any(query, model, kwargs):
    """
    Returns a query object that allows any kwarg
    to be present.

    :param query:
    :param model:
    :param kwargs:
    :return:
    """
    or_args = []
    for attr, value in kwargs.items():
        or_args.append(or_(getattr(model, attr) == value))
    exprs = or_(*or_args)
    return query.filter(exprs)


def get(model, value, field="id"):
    """
    Returns one object filtered by the field and value.

    :param model:
    :param value:
    :param field:
    :return:
    """
    query = session_query(model)
    return query.filter(getattr(model, field) == value).scalar()


def get_all(model, value, field="id"):
    """
    Returns query object with the fields and value filtered.

    :param model:
    :param value:
    :param field:
    :return:
    """
    query = session_query(model)
    return query.filter(getattr(model, field) == value)


def create(model):
    """
    Helper that attempts to create a new instance of an object.

    :param model:
    :return: :raise IntegrityError:
    """
    try:
        db.session.add(model)
        commit()
    except exc.IntegrityError as e:
        raise DuplicateError(e.orig.diag.message_detail)

    db.session.refresh(model)
    return model


def update(model):
    """
    Helper that attempts to update a model.

    :param model:
    :return:
    """
    commit()
    db.session.refresh(model)
    return model


def delete(model):
    """
    Helper that attempts to delete a model.

    :param model:
    """
    if model:
        db.session.delete(model)
        db.session.commit()


def filter(query, model, terms):
    """
    Helper that searched for 'like' strings in column values.

    :param query:
    :param model:
    :param terms:
    :return:
    """
    return query.filter(getattr(model, terms[0]).ilike('%{}%'.format(terms[1])))


def sort(query, model, field, direction):
    """
    Returns objects of the specified `model` in the field and direction
    given

    :param query:
    :param model:
    :param field:
    :param direction:
    """
    try:
        field = getattr(model, field)
        direction = getattr(field, direction)
        query = query.order_by(direction())
        return query
    except AttributeError:
        raise AttrNotFound(field)


def paginate(query, page, count):
    """
    Returns the items given the count and page specified

    :param query:
    :param page:
    :param count:
    """
    return query.paginate(page, count)


def update_list(model, model_attr, item_model, items):
    """
    Helper that correctly updates a models items
    depending on what has changed

    :param model_attr:
    :param item_model:
    :param items:
    :param model:
    :return:
    """
    ids = []

    for i in getattr(model, model_attr):
        if i.id not in ids:
            getattr(model, model_attr).remove(i)

    for i in items:
        for item in getattr(model, model_attr):
            if item.id == i['id']:
                break
        else:
            getattr(model, model_attr).append(get(item_model, i['id']))

    return model


def clone(model):
    """
    Clones the given model and removes it's primary key
    :param model:
    :return:
    """
    db.session.expunge(model)
    make_transient(model)
    model.id = None
    return model


def sort_and_page(query, model, args):
    """
    Helper that allows us to combine sorting and paging

    :param query:
    :param model:
    :param args:
    :return:
    """
    sort_by = args.pop('sort_by')
    sort_dir = args.pop('sort_dir')
    page = args.pop('page')
    count = args.pop('count')

    query = find_all(query, model, args)

    if sort_by and sort_dir:
        query = sort(query, model, sort_by, sort_dir)

    total = query.count()

    # offset calculated at zero
    page -= 1
    items = query.offset(count * page).limit(count).all()
    return dict(items=items, total=total)
