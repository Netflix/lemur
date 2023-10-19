"""
.. module: lemur.database
    :platform: Unix
    :synopsis: This module contains all of the database related methods
    needed for lemur to interact with a datastore

    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from inflection import underscore
from flask_sqlalchemy.model import DefaultMeta
from sqlalchemy import exc, func, distinct
from sqlalchemy.orm import make_transient, lazyload
from sqlalchemy.sql import and_, or_

from lemur.exceptions import AttrNotFound, DuplicateError
from lemur.extensions import db


BaseModel: DefaultMeta = db.Model


def filter_none(kwargs):
    """
    Remove all `None` values from a  given dict. SQLAlchemy does not
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
    return model.query if hasattr(model, "query") else db.session.query(model)


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


def rollback():
    """
    Helper to rollback the current session.
    """
    db.session.rollback()


def add(model):
    """
    Helper to add a `model` to the current session.

    :param model:
    :return:
    """
    db.session.add(model)


def get_model_column(model, field):
    if field in getattr(model, "sensitive_fields", ()):
        raise AttrNotFound(field)
    column = model.__table__.columns.get(field, None)
    if column is None:
        raise AttrNotFound(field)

    return column


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
            value = value.split(",")

        conditions.append(get_model_column(model, attr).in_(value))

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
        or_args.append(or_(get_model_column(model, attr) == value))
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
    return query.filter(get_model_column(model, field) == value).scalar()


def get_all(model, value, field="id"):
    """
    Returns query object with the fields and value filtered.

    :param model:
    :param value:
    :param field:
    :return:
    """
    query = session_query(model)
    return query.filter(get_model_column(model, field) == value)


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
    column = get_model_column(model, underscore(terms[0]))
    return query.filter(column.ilike(f"%{terms[1]}%"))


def sort(query, model, field, direction):
    """
    Returns objects of the specified `model` in the field and direction
    given

    :param query:
    :param model:
    :param field:
    :param direction:
    """
    column = get_model_column(model, underscore(field))
    return query.order_by(column.desc() if direction == "desc" else column.asc())


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
            if item.id == i["id"]:
                break
        else:
            getattr(model, model_attr).append(get(item_model, i["id"]))

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


def get_count(q):
    """
    Count the number of rows in a table. More efficient than count(*)
    :param q:
    :return:
    """
    disable_group_by = False
    if len(q._entities) > 1:
        # currently support only one entity
        raise Exception("only one entity is supported for get_count, got: %s" % q)
    entity = q._entities[0]
    if hasattr(entity, "column"):
        # _ColumnEntity has column attr - on case: query(Model.column)...
        col = entity.column
        if q._group_by and q._distinct:
            # which query can have both?
            raise NotImplementedError
        if q._group_by or q._distinct:
            col = distinct(col)
        if q._group_by:
            # need to disable group_by and enable distinct - we can do this because we have only 1 entity
            disable_group_by = True
        count_func = func.count(col)
    else:
        # _MapperEntity doesn't have column attr - on case: query(Model)...
        count_func = func.count()
    if q._group_by and not disable_group_by:
        count_func = count_func.over(None)
    count_q = (
        q.options(lazyload("*"))
        .statement.with_only_columns([count_func])
        .order_by(None)
    )
    if disable_group_by:
        count_q = count_q.group_by(None)
    try:
        count = q.session.execute(count_q).scalar()
    except Exception:
        raise Exception("error executing query")
    return count


def sort_and_page(query, model, args):
    """
    Helper that allows us to combine sorting and paging. Note that paging is not safe unless combined with sorting.

    :param query: search query
    :param model: model to use for resulting items
    :param args: arguments to query with, including sorting and paging parameters
    :return: the items given the count and page specified
    """
    sort_by = args.pop("sort_by")
    sort_dir = args.pop("sort_dir")
    page = args.pop("page")
    count = args.pop("count")

    if args.get("user"):
        user = args.pop("user")

    query = find_all(query, model, args)

    if sort_by and sort_dir:
        query = sort(query, model, sort_by, sort_dir)

    total = get_count(query)

    # offset calculated at zero
    page -= 1
    # this is equivalent to query.paginate(page, count) where page has not been pre-decremented
    items = query.offset(count * page).limit(count).all()
    return dict(items=items, total=total)
