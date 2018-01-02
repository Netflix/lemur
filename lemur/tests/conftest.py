import os

import datetime
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from flask import current_app
from flask_principal import identity_changed, Identity

from lemur import create_app
from lemur.database import db as _db
from lemur.auth.service import create_token
from lemur.tests.vectors import PRIVATE_KEY_STR

from .factories import ApiKeyFactory, AuthorityFactory, NotificationFactory, DestinationFactory, \
    CertificateFactory, UserFactory, RoleFactory, SourceFactory, EndpointFactory, RotationPolicyFactory


def pytest_runtest_setup(item):
    if 'slow' in item.keywords and not item.config.getoption("--runslow"):
        pytest.skip("need --runslow option to run")

    if "incremental" in item.keywords:
        previousfailed = getattr(item.parent, "_previousfailed", None)
        if previousfailed is not None:
            pytest.xfail("previous test failed ({0})".format(previousfailed.name))


def pytest_runtest_makereport(item, call):
    if "incremental" in item.keywords:
        if call.excinfo is not None:
            parent = item.parent
            parent._previousfailed = item


@pytest.yield_fixture(scope="session")
def app(request):
    """
    Creates a new Flask application for a test duration.
    Uses application factory `create_app`.
    """
    _app = create_app(os.path.dirname(os.path.realpath(__file__)) + '/conf.py')
    ctx = _app.app_context()
    ctx.push()

    yield _app

    ctx.pop()


@pytest.yield_fixture(scope="session")
def db(app, request):
    _db.drop_all()
    _db.create_all()

    _db.app = app

    UserFactory()
    r = RoleFactory(name='admin')
    u = UserFactory(roles=[r])
    rp = RotationPolicyFactory(name='default')
    ApiKeyFactory(user=u)

    _db.session.commit()
    yield _db
    _db.drop_all()


@pytest.yield_fixture(scope="function")
def session(db, request):
    """
    Creates a new database session with (with working transaction)
    for test duration.
    """
    db.session.begin_nested()
    yield db.session
    db.session.rollback()


@pytest.yield_fixture(scope="function")
def client(app, session, client):
    yield client


@pytest.fixture
def authority(session):
    a = AuthorityFactory()
    session.commit()
    return a


@pytest.fixture
def destination(session):
    d = DestinationFactory()
    session.commit()
    return d


@pytest.fixture
def source(session):
    s = SourceFactory()
    session.commit()
    return s


@pytest.fixture
def notification(session):
    n = NotificationFactory()
    session.commit()
    return n


@pytest.fixture
def certificate(session):
    u = UserFactory()
    a = AuthorityFactory()
    c = CertificateFactory(user=u, authority=a)
    session.commit()
    return c


@pytest.fixture
def endpoint(session):
    s = SourceFactory()
    e = EndpointFactory(source=s)
    session.commit()
    return e


@pytest.fixture
def role(session):
    r = RoleFactory()
    session.commit()
    return r


@pytest.fixture
def user(session):
    u = UserFactory()
    session.commit()
    user_token = create_token(u)
    token = {'Authorization': 'Basic ' + user_token}
    return {'user': u, 'token': token}


@pytest.fixture
def admin_user(session):
    u = UserFactory()
    admin_role = RoleFactory(name='admin')
    u.roles.append(admin_role)
    session.commit()
    user_token = create_token(u)
    token = {'Authorization': 'Basic ' + user_token}
    return {'user': u, 'token': token}


@pytest.fixture
def issuer_plugin():
    from lemur.plugins.base import register
    from .plugins.issuer_plugin import TestIssuerPlugin
    register(TestIssuerPlugin)
    return TestIssuerPlugin


@pytest.fixture
def notification_plugin():
    from lemur.plugins.base import register
    from .plugins.notification_plugin import TestNotificationPlugin
    register(TestNotificationPlugin)
    return TestNotificationPlugin


@pytest.fixture
def destination_plugin():
    from lemur.plugins.base import register
    from .plugins.destination_plugin import TestDestinationPlugin
    register(TestDestinationPlugin)
    return TestDestinationPlugin


@pytest.fixture
def source_plugin():
    from lemur.plugins.base import register
    from .plugins.source_plugin import TestSourcePlugin
    register(TestSourcePlugin)
    return TestSourcePlugin


@pytest.yield_fixture(scope="function")
def logged_in_user(session, app):
    with app.test_request_context():
        identity_changed.send(current_app._get_current_object(), identity=Identity(1))
        yield


@pytest.yield_fixture(scope="function")
def logged_in_admin(session, app):
    with app.test_request_context():
        identity_changed.send(current_app._get_current_object(), identity=Identity(2))
        yield


@pytest.fixture
def private_key():
    return load_pem_private_key(PRIVATE_KEY_STR.encode(), password=None, backend=default_backend())


@pytest.fixture
def cert_builder(private_key):
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'foo.com')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'foo.com')]))
            .serial_number(1)
            .public_key(private_key.public_key())
            .not_valid_before(datetime.datetime(2017, 12, 22))
            .not_valid_after(datetime.datetime(2040, 1, 1)))
