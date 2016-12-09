from lemur import database
from lemur.certificates.models import Certificate


def certificates(owner=None, issuer=None, validity=None, deployed=None):
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


def fqdns(owner=None, issuer=None, validity=None, deployed=None):
    """
    Returns an FQDN report.
    :param owner:
    :param issuer:
    :param validity:
    :param deployed:
    :return:
    """
    for cert in certificates(validity=validity, deployed=deployed):
        headers = ['FQDN', 'Root Domain', 'Issuer', 'Total Length (days), Time Until Expiration (days)']
        pass
