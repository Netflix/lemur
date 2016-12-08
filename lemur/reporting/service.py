from lemur import database
from lemur.certificates.models import Certificate


def certificates(validity=None, deployed=None):
    """
    Filters certificates by the given dimensions.

    :param validity:
    :param deployed:
    :return:
    """
    query = database.session_query(Certificate)

    if validity == 'expired':
        query = query.filter(Certificate.expired == True)  # noqa

    elif validity == 'valid':
        query = query.filter(Certificate.expired == False)  # noqa

    return query.all()


def fqdns(validity=None, deployed=None):
    """
    Returns an FQDN report.
    :param validity:
    :param deployed:
    :return:
    """
    for cert in certificates(validity=validity, deployed=deployed):
        pass
