import os
import pytest

from flask import current_app

from flask.ext.principal import identity_changed, Identity

from lemur import create_app
from lemur.database import db as _db

from .factories import AuthorityFactory, NotificationFactory, DestinationFactory, \
    CertificateFactory, UserFactory, RoleFactory


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
    UserFactory(roles=[r])

    _db.session.commit()
    yield _db


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
def notification(session):
    n = NotificationFactory()
    session.commit()
    return n


@pytest.fixture
def certificate(session):
    c = CertificateFactory()
    session.commit()
    return c


@pytest.fixture
def role(session):
    r = RoleFactory()
    session.commit()
    return r


@pytest.yield_fixture(scope="function")
def logged_in_user(app, user):
    with app.test_request_context():
        identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
        yield


@pytest.yield_fixture(scope="function")
def logged_in_admin(app, admin_user):
    with app.test_request_context():
        identity_changed.send(current_app._get_current_object(), identity=Identity(admin_user.id))
        yield
