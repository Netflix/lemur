Contributing
============

Want to contribute back to Lemur? This page describes the general development flow,
our philosophy, the test suite, and issue tracking.


Documentation
-------------

If you're looking to help document Lemur, you can get set up with Sphinx, our documentation tool,
but first you will want to make sure you have a few things on your local system:

* python-dev (if you're on OS X, you already have this)
* pip
* virtualenvwrapper

Once you've got all that, the rest is simple:

::

    # If you have a fork, you'll want to clone it instead
    git clone git://github.com/netflix/lemur.git

    # Create and activate python virtualenv from within the lemur repo
    python3 -m venv env
    . env/bin/activate

    # Install doc requirements

    make dev-docs

    # Make the docs
    cd docs
    make html

Running ``make dev-docs`` will install the basic requirements to get Sphinx running.


Building Documentation
~~~~~~~~~~~~~~~~~~~~~~

Inside the ``docs`` directory, you can run ``make`` to build the documentation.
See ``make help`` for available options and the `Sphinx Documentation <http://sphinx-doc.org/contents.html>`_ for more information.

Adding New Modules to Documentation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a new module is added, it will need to be added to the documentation.
Ideally, we might rely on `sphinx-apidoc <https://www.sphinx-doc.org/en/master/man/sphinx-apidoc.html>`_ to autogenerate our documentation.
Unfortunately, this causes some build problems.
Instead, you'll need to add new modules by hand.

Developing Against HEAD
-----------------------

We try to make it easy to get up and running in a development environment using a git checkout
of Lemur. There are two ways to run Lemur locally: directly on your development machine, or
in a Docker container.

**Running in a Docker container**

Look at the `lemur-docker <https://github.com/Netflix/lemur-docker>`_ project.
Usage instructions are self-contained in the README for that project.

**Running directly on your development machine**

You'll want to make sure you have a few things on your local system first:

* python-dev (if you're on OS X, you already have this)
* pip
* virtualenv (ideally virtualenvwrapper)
* node.js (for npm and building css/javascript)
* `PostgreSQL <https://lemur.readthedocs.io/en/latest/quickstart/index.html#setup-postgres>`_

Once you've got all that, the rest is simple:

::

    # If you have a fork, you'll want to clone it instead
    git clone git://github.com/lemur/lemur.git

    # Create a python virtualenv
    python3 -m venv env

    # Make the magic happen
    make

Running ``make`` will do several things, including:

* Setting up any submodules (including Bootstrap)
* Installing Python requirements
* Installing NPM requirements

.. note::
    You will want to store your virtualenv out of the ``lemur`` directory you cloned above,
    otherwise ``make`` will fail.

Create a default Lemur configuration just as if this were a production instance:

::

    lemur create_config
    lemur init

You'll likely want to make some changes to the default configuration (we recommend developing against Postgres, for example). Once done, migrate your database using the following command:

::

	lemur upgrade


.. note:: The ``upgrade`` shortcut is simply a shortcut to Alembic's upgrade command.


Running tests with Docker and docker-compose
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you just want to run tests in a Docker container, you can use Docker and docker-compose for running the tests with ``docker-compose run test`` directly in the ``lemur`` project.

(For running the Lemur service in Docker, see `lemur-docker <https://github.com/Netflix/lemur-docker>`_.)


Coding Standards
----------------

Lemur follows the guidelines laid out in `pep8 <http://www.python.org/dev/peps/pep-0008/>`_  with a little bit
of flexibility on things like line length. We always give way for the `Zen of Python <http://www.python.org/dev/peps/pep-0020/>`_. We also use strict mode for JavaScript, enforced by jshint.

You can run all linters with ``make lint``, or respectively ``lint-python`` or ``lint-js``.

Spacing
~~~~~~~

Python:
  4 Spaces

JavaScript:
  2 Spaces

CSS:
  2 Spaces

HTML:
  2 Spaces


Git hooks
~~~~~~~~~

To help developers maintain the above standards, Lemur includes a configuration file for Yelp's `pre-commit <http://pre-commit.com/>`_. This is an optional dependency and is not required in order to contribute to Lemur.


Running the Test Suite
----------------------

The test suite consists of multiple parts, testing both the Python and JavaScript components in Lemur. If you've setup your environment correctly, you can run the entire suite with the following command:

::

    make test

If you only need to run the Python tests, you can do so with ``make test-python``, as well as ``make test-js`` for the JavaScript tests.


You'll notice that the test suite is structured based on where the code lives, and strongly encourages using the mock library to drive more accurate individual tests.

.. note:: We use py.test for the Python test suite, and a combination of phantomjs and jasmine for the JavaScript tests.


Static Media
------------

Lemur uses a library that compiles its static media assets (LESS and JS files) automatically. If you're developing using
runserver you'll see changes happen not only in the original files, but also the minified or processed versions of the file.

If you've made changes and need to compile them by hand for any reason, you can do so by running:

::

    lemur compilestatic

The minified and processed files should be committed alongside the unprocessed changes.

It's also important to note that Lemur's frontend and API are not tied together. The API does not serve any of the static assets, we rely on nginx or some other file server to server all of the static assets.
During development that means we need an additional server to serve those static files for the GUI.

This is accomplished with a Gulp task:

::

    ./node_modules/.bin/gulp serve

The gulp task compiles all the JS/CSS/HTML files and opens the Lemur welcome page in your default browsers. Additionally any changes to made to the JS/CSS/HTML with be reloaded in your browsers.

Developing with Flask
---------------------

Because Lemur is just Flask, you can use all of the standard Flask functionality. The only difference is you'll be accessing commands that would normally go through manage.py using the ``lemur`` CLI helper instead.

For example, you probably don't want to use ``lemur start`` for development, as it doesn't support anything like
automatic reloading on code changes. For that you'd want to use the standard builtin ``runserver`` command:

::

	lemur runserver


DDL (Schema Changes)
--------------------

Schema changes should always introduce the new schema in a commit, and then introduce code relying on that schema in a followup commit. This also means that new columns must be NULLable.

Removing columns and tables requires a slightly more painful flow, and should resemble the follow multi-commit flow:

- Remove all references to the column or table (but don't remove the Model itself)
- Remove the model code
- Remove the table or column


Contributing Back Code
----------------------

All patches should be sent as a pull request on GitHub, include tests, and documentation where needed. If you're fixing a bug or making a large change the patch **must** include test coverage.

Uncertain about how to write tests? Take a look at some existing tests that are similar to the code you're changing, and go from there.

You can see a list of open pull requests (pending changes) by visiting https://github.com/netflix/lemur/pulls

Pull requests should be against **main** and pass all TravisCI checks


Writing a Plugin
================

.. toctree::
    :maxdepth: 2

    plugins/index


REST API
========

Lemur's front end is entirely API driven. Any action that you can accomplish via the UI can also be accomplished by the
API. The following is documents and provides examples on how to make requests to the Lemur API.

Authentication
--------------

.. automodule:: lemur.auth.views
    :members:
    :undoc-members:
    :show-inheritance:

Destinations
------------

.. automodule:: lemur.destinations.views
    :members:
    :undoc-members:
    :show-inheritance:

Notifications
-------------

.. automodule:: lemur.notifications.views
    :members:
    :undoc-members:
    :show-inheritance:

Users
-----

.. automodule:: lemur.users.views
    :members:
    :undoc-members:
    :show-inheritance:

Roles
-----

.. automodule:: lemur.roles.views
    :members:
    :undoc-members:
    :show-inheritance:

Certificates
------------

.. automodule:: lemur.certificates.views
    :members:
    :undoc-members:
    :show-inheritance:

Authorities
-----------

.. automodule:: lemur.authorities.views
    :members:
    :undoc-members:
    :show-inheritance:

Domains
-------

.. automodule:: lemur.domains.views
    :members:
    :undoc-members:
    :show-inheritance:

Endpoints
---------

.. automodule:: lemur.endpoints.views
    :members:
    :undoc-members:
    :show-inheritance:

Logs
----

.. automodule:: lemur.logs.views
    :members:
    :undoc-members:
    :show-inheritance:


Sources
-------

.. automodule:: lemur.sources.views
    :members:
    :undoc-members:
    :show-inheritance:


Internals
=========

.. toctree::
    :maxdepth: 2

    internals/lemur
