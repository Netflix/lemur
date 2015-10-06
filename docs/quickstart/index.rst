Quickstart
**********

This guide will step you through setting up a Python-based virtualenv, installing the required packages, and configuring the basic web service.
This guide assumes a clean Ubuntu 14.04 instance, commands may differ based on the OS and configuration being used.

Pressed for time? See the Lemur docker file on `Github <https://github.com/Netflix/lemur-docker>`_.

Dependencies
------------

Some basic prerequisites which you'll need in order to run Lemur:

* A UNIX-based operating system. We test on Ubuntu, develop on OS X
* Python 2.7
* PostgreSQL
* Nginx

.. note:: Lemur was built with in AWS in mind. This means that things such as databases (RDS), mail (SES), and TLS (ELB),
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


Installing build dependencies
-----------------------------

If installing Lemur on truely bare Ubuntu OS you will need to grab the following packages so that Lemur can correctly build it's
dependencies::

    $ sudo apt-get update
    $ sudo apt-get install nodejs-legacy python-pip libpq-dev python-dev build-essential libssl-dev libffi-dev nginx git supervisor

And optionally if your database is going to be on the same host as the webserver::

    $ sudo apt-get install postgresql


Installing from Source
~~~~~~~~~~~~~~~~~~~~~~

If you're installing the Lemur source (e.g. from git), you'll also need to install **npm**.

Once your system is prepared, ensure that you are in the virtualenv:

.. code-block:: bash

  $ which python


And then run:

.. code-block:: bash

  $ make develop

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

Update your configuration
-------------------------

Once created you will need to update the configuration file with information about your environment,
such as which database to talk to, where keys are stored etc..

.. Note:: If you are unfamiliar with with the SQLALCHEMY_DATABASE_URI string it can be broken up like so:
      postgresql://userame:password@databasefqdn:databaseport/databasename

Setup Postgres
--------------

For production a dedicated database is recommended, for this guide we will assume postgres has been installed and is on
the same machine that Lemur is installed on.

First, set a password for the postgres user.  For this guide, we will use **lemur** as an example but you should use the database password generated for by Lemur::

     $ sudo -u postgres psql postgres
     # \password postgres
     Enter new password: lemur
     Enter it again: lemur

Type CTRL-D to exit psql once you have changed the password.

Next, we will create our new database::

     $ sudo -u postgres createdb lemur

.. _InitializingLemur:

Initializing Lemur
------------------

Lemur provides a helpful command that will initialize your database for you. It creates a default user (lemur) that is
used by Lemur to help associate certificates that do not currently have an owner. This is most commonly the case when
Lemur has discovered certificates from a third party source. This is also a default user that can be used to
administer Lemur.

In addition to creating a new user, Lemur also creates a few default email notifications. These notifications are based
on a few configuration options such as `LEMUR_SECURITY_TEAM_EMAIL`. They basically guarantee that every cerificate within
Lemur will send one expiration notification to the security team.

Additional notifications can be created through the UI or API.
See :ref:`Creating Notifications <CreatingNotifications>` and :ref:`Command Line Interface <CommandLineInterface>` for details.

**Make note of the password used as this will be used during first login to the Lemur UI**

.. code-block:: bash

    $ lemur db init

.. code-block:: bash

    $ lemur init

.. note:: It is recommended that once the 'lemur' user is created that you create individual users for every day access.
    There is currently no way for a user to self enroll for Lemur access, they must have an administrator create an account
    for them or be enrolled automatically through SSO. This can be done through the CLI or UI.
    See :ref:`Creating Users <CreatingUsers>` and :ref:`Command Line Interface <CommandLineInterface>` for details

Setup a Reverse Proxy
---------------------

By default, Lemur runs on port 5000. Even if you change this, under normal conditions you won't be able to bind to
port 80. To get around this (and to avoid running Lemur as a privileged user, which you shouldn't), we need setup a
simple web proxy. There are many different web servers you can use for this, we like and recommend Nginx.

Proxying with Nginx
~~~~~~~~~~~~~~~~~~~

You'll use the builtin HttpProxyModule within Nginx to handle proxying

::

   location /api {
        proxy_pass  http://127.0.0.1:5000;
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
        proxy_redirect off;
        proxy_buffering off;
        proxy_set_header        Host            $host;
        proxy_set_header        X-Real-IP       $remote_addr;
        proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    location / {
        root /www/lemur/lemur/static/dist;
        include mime.types;
        index index.html;
    }

See :doc:`../production/index` for more details on using Nginx.


Starting the Web Service
------------------------

Lemur provides a built-in webserver (powered by gunicorn and eventlet) to get you off the ground quickly.

To start the webserver, you simply use ``lemur start``. If you opted to use an alternative configuration path
you can pass that via the --config option.

.. note::
    You can login with the default user created during :ref:`Initializing Lemur <InitializingLemur>` or any other
    user you may have created.

::

  # Lemur's server runs on port 5000 by default. Make sure your client reflects
  # the correct host and port!
  lemur --config=/etc/lemur.conf.py start -b 127.0.0.1:5000

You should now be able to test the web service by visiting `http://localhost:5000/`.

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

Lemur uses periodic sync tasks to make sure it is up-to-date with its environment. As always things can change outside
of Lemur, but we do our best to reconcile those changes.

.. code-block:: bash

  $ crontab -e
  * 3 * * * lemur sync --all
  * 3 * * * lemur check_revoked

Additional Utilities
--------------------

If you're familiar with Python you'll quickly find yourself at home, and even more so if you've used Flask. The
``lemur`` command is just a simple wrapper around Flask's ``manage.py``, which means you get all of the
power and flexibility that goes with it.

Some of the features which you'll likely find useful are:

lock
~~~~

Encrypts sensitive key material - This is most useful for storing encrypted secrets in source code.

unlock
~~~~~~

Decrypts sensitive key material - Used to decrypt the secrets stored in source during deployment.


What's Next?
------------

Get familiar with how Lemur works by reviewing the :doc:`../guide/index`. When you're ready
see :doc:`../production/index` for more details on how to configure Lemur for production.

The above just gets you going, but for production there are several different security considerations to take into account.
Remember, Lemur is handling sensitive data and security is imperative.

