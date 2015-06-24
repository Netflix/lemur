import pytest

from lemur import create_app
from lemur.database import db as _db

from flask.ext.sqlalchemy import SignallingSession

from sqlalchemy import event


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

    ctx = app.app_context()
    ctx.push()

    yield app

    ctx.pop()


@pytest.yield_fixture(scope="session")
def db():
    _db.create_all()

    yield _db

    _db.drop_all()


@pytest.yield_fixture(scope="function")
def session(app, db):
    """
    Creates a new database session with (with working transaction)
    for test duration.
    """
    connection = _db.engine.connect()
    transaction = connection.begin()

    options = dict(bind=connection)
    session = _db.create_scoped_session(options=options)

    # then each time that SAVEPOINT ends, reopen it
    @event.listens_for(SignallingSession, "after_transaction_end")
    def restart_savepoint(session, transaction):
        if transaction.nested and not transaction._parent.nested:

            # ensure that state is expired the way
            # session.commit() at the top level normally does
            # (optional step)
            session.expire_all()

            session.begin_nested()

    # pushing new Flask application context for multiple-thread
    # tests to work

    _db.session = session

    yield session

    # the code after the yield statement works as a teardown
    transaction.rollback()
    connection.close()
    session.remove()
