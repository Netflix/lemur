import arrow
from datetime import timedelta

from sqlalchemy import cast, not_
from sqlalchemy_utils import ArrowType

from lemur import database
from lemur.certificates.models import Certificate


def filter_by_validity(query, validity=None):
    if validity == "expired":
        query = query.filter(Certificate.expired == True)  # noqa

    elif validity == "valid":
        query = query.filter(Certificate.expired == False)  # noqa

    return query


def filter_by_owner(query, owner=None):
    if owner:
        return query.filter(Certificate.owner == owner)

    return query


def filter_by_issuer(query, issuer=None):
    if issuer:
        return query.filter(Certificate.issuer == issuer)

    return query


def filter_by_deployment(query, deployment=None):
    if deployment == "deployed":
        query = query.filter(Certificate.endpoints.any())

    elif deployment == "ready":
        query = query.filter(not_(Certificate.endpoints.any()))

    return query


def filter_by_validity_end(query, validity_end=None):
    if validity_end:
        return query.filter(cast(Certificate.not_after, ArrowType) <= validity_end)

    return query


def fqdns(**kwargs):
    """
    Returns an FQDN report.
    :return:
    """
    query = database.session_query(Certificate)
    query = filter_by_deployment(query, deployment=kwargs.get("deployed"))
    query = filter_by_validity(query, validity=kwargs.get("validity"))
    return query


def expiring_certificates(**kwargs):
    """
    Returns an Expiring report.
    :return:
    """
    ttl = kwargs.get("ttl", 30)
    now = arrow.utcnow()
    validity_end = now + timedelta(days=ttl)

    query = database.session_query(Certificate)
    query = filter_by_deployment(query, deployment=kwargs.get("deployed"))
    query = filter_by_validity(query, validity="valid")
    query = filter_by_validity_end(query, validity_end=validity_end)

    return query
