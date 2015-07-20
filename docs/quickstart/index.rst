Quickstart
**********

This guide will step you through setting up a Python-based virtualenv, installing the required packages, and configuring the basic web service.

Dependencies
------------

Some basic prerequisites which you'll need in order to run Lemur:

* A UNIX-based operating system. We test on Ubuntu, develop on OS X
* Python 2.7
* PostgreSQL
* Ngnix

.. note:: Lemur was built with in AWS in mind. This means that things such as databases (RDS), mail (SES), and SSL (ELB),
    are largely handled for us. Lemur does **not** require AWS to function. Our guides and documentation try to be
    be as generic as possible and are not intended to document every step of launching Lemur into a given environment.

Setting up an Environment
-------------------------

The first thing you'll need is the Python ``virtualenv`` package. You probably already
have this, but if not, you can install it with::

  pip install -U virtualenv

Once that's done, choose a location for the environment, and create it with the ``virtualenv``
command. For our guide, we're going to choose ``/www/lemur/``::

  virtualenv /www/lemur/

Finally, activate your virtualenv::

  source /www/lemur/bin/activate

.. note:: Activating the environment adjusts your PATH, so that things like pip now
          install into the virtualenv by default.


Installing Lemur
----------------

Once you've got the environment setup, you can install Lemur and all its dependencies with
the same command you used to grab virtualenv::

    pip install -U lemur

Once everything is installed, you should be able to execute the Lemur CLI, via ``lemur``, and get something
like the following:

.. code-block:: bash

  $ lemur
  usage: lemur [--config=/path/to/settings.py] [command] [options]


Installing from Source
~~~~~~~~~~~~~~~~~~~~~~

If you're installing the Lemur source (e.g. from git), you'll also need to install **npm**.

Once your system is prepared, symlink your source into the virtualenv:

.. code-block:: bash

  $ python setup.py develop

.. Note:: This command will install npm dependencies as well as compile static assets.


Creating a configuration
------------------------

Before we run Lemur we must create a valid configuration file for it.

The Lemur cli comes with a simple command to get you up and running quickly.

Simply run:

.. code-block:: bash

  $ lemur create_config

.. Note:: This command will create a default configuration under `~/.lemur/lemur.conf.py` you
    can specify this location by passing the `config_path` parameter to the `create_config` command.

You can specify `-c` or `--config` to any Lemur command to specify the current environment
you are working in. Lemur will also look under the environmental variable `LEMUR_CONF` should
that be easier to setup in your environment.

Once created you will need to update the configuration file with information about your environment,
such as which database to talk to, where keys are stores etc..

Initializing Lemur
------------------

Lemur provides a helpful command that will initialize your database for you. It creates a default user (lemur) that is
used by Lemur to help associate certificates that do not currently have an owner. This is most commonly the case when
Lemur has discovered certificates from a third party resource. This is also a default user that can be used to
administer Lemur.

.. code-block:: bash

    $ lemur db init

.. code-block:: bash

    $ lemur init

.. note:: It is recommended that once the 'lemur' user is created that you create individual users for every day access.
    There is currently no way for a user to self enroll for Lemur access, they must have an administrator create an account
    for them or be enrolled automatically through SSO. This can be done through the CLI or UI.
    See :ref:`Creating Users <CreatingUsers>` and :ref:`Command Line Interface <CommandLineInterface>` for details

.. note::
    This assumes you have already created a postgres database and have specified the right postgres URI in the
    lemur configuration. See the `Postgres Documentation <http://www.postgresql.org/docs/9.0/static/tutorial-createdb.html>`_
    for details.


Starting the Web Service
------------------------

Lemur provides a built-in webserver (powered by gunicorn and eventlet) to get you off the ground quickly.

To start the webserver, you simply use ``lemur start``. If you opted to use an alternative configuration path
you can pass that via the --config option.

::

  # Lemur's server runs on port 5000 by default. Make sure your client reflects
  # the correct host and port!
  lemur --config=/etc/lemur.conf.py start

You should now be able to test the web service by visiting `http://localhost:5000/`.

Setup a Reverse Proxy
---------------------

By default, Lemur runs on port 5000. Even if you change this, under normal conditions you won't be able to bind to
port 80. To get around this (and to avoid running Lemur as a privileged user, which you shouldn't), we recommend
you setup a simple web proxy.

Proxying with Nginx
~~~~~~~~~~~~~~~~~~~

You'll use the builtin HttpProxyModule within Nginx to handle proxying::

    location / {
<<<<<<< HEAD
      proxy_pass         http://localhost:5000;
      proxy_redirect     off;

      proxy_set_header   Host              $host;
      proxy_set_header   X-Real-IP         $remote_addr;
      proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
      proxy_set_header   X-Forwarded-Proto $scheme;
=======
        root /www/lemur/lemur/static/dist;
        include mime.types;
        index index.html;
>>>>>>> b978435... Merge pull request #21 from kevgliss/buildfixes
    }

See :doc:`../production/index` for more details on using Nginx.

Proxying with Apache
~~~~~~~~~~~~~~~~~~~~

Apache requires the use of mod_proxy for forwarding requests::

    ProxyPass / http://localhost:5000/
    ProxyPassReverse / http://localhost:5000/
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https" env=HTTPS

You will need to enable ``headers``, ``proxy``, and ``proxy_http`` apache modules to use these settings.

See :doc:`../production/index` for more details on using Apache.


Running Lemur as a Service
---------------------------

We recommend using whatever software you are most familiar with for managing Lemur processes. One option is
`Supervisor <http://supervisord.org/>`_.

Configure ``supervisord``
~~~~~~~~~~~~~~~~~~~~~~~~~

Configuring Supervisor couldn't be more simple. Just point it to the ``lemur`` executable in your virtualenv's bin/
folder and you're good to go.

::

  [program:lemur-web]
  directory=/www/lemur/
  command=/www/lemur/bin/lemur start
  autostart=true
  autorestart=true
  redirect_stderr=true
  stdout_logfile syslog
  stderr_logfile syslog

See :ref:`Using Supervisor <UsingSupervisor>` for more details on using Supervisor.

Syncing
-------

Lemur uses periodic sync tasks to make sure it is up-to-date with it's environment. As always things can change outside
of Lemur, but we do our best to reconcile those changes.

.. code-block:: bash

  $ crontab -e
  * 3 * * * lemur sync
  * 3 * * * lemur check_revoked

Additional Utilities
--------------------

If you're familiar with Python you'll quickly find yourself at home, and even more so if you've used Flask. The
``lemur`` command is just a simple wrapper around Flask's ``manage.py``, which means you get all of the
power and flexibility that goes with it.

Some of those which you'll likely find useful are:

lock
~~~~

Encrypts sensitive key material - This is most useful for storing encrypted secrets in source code.

unlock
~~~~~~

Decrypts sensitive key material - Used to decrypt the secrets stored in source during deployment.


What's Next?
------------

The above gets you going, but for production there are several different security considerations to take into account,
remember Lemur is handling sensitive data and security is imperative.

See :doc:`../production/index` for more details on how to configure Lemur for production.

