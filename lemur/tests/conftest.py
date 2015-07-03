import os
import pytest

from lemur import create_app
from lemur.database import db as _db
from lemur.users import service as user_service
from lemur.roles import service as role_service


def pytest_addoption(parser):
    parser.addoption("--runslow", action="store_true", help="run slow tests")


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
def app():
    """
    Creates a new Flask application for a test duration.
    Uses application factory `create_app`.
    """
    app = create_app()
    app.config['TESTING'] = True
    app.config['LEMUR_ENCRYPTION_KEY'] = 'test'

    ctx = app.app_context()
    ctx.push()

    yield app

    ctx.pop()



@pytest.yield_fixture(scope="session")
def db(app, request):
    _db.drop_all()
    _db.create_all()

    _db.app = app

    user = user_service.create('user', 'test', 'user@example.com', True, None, [])
    admin_role = role_service.create('admin')
    admin = user_service.create('admin', 'admin', 'admin@example.com', True, None, [admin_role])
    _db.session.commit()
    yield _db


@pytest.yield_fixture(scope="function")
def session(db, request):
    """
    Creates a new database session with (with working transaction)
    for test duration.
    """
    db.session.begin_nested()
    yield session
    db.session.rollback()


@pytest.yield_fixture(scope="function")
def client(app, session):
    with app.test_client() as client:
        yield client

