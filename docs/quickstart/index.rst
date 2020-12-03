Quickstart
**********

This guide will step you through setting up a Python-based virtualenv, installing the required packages, and configuring the basic web service.  This guide assumes a clean Ubuntu 14.04 instance, commands may differ based on the OS and configuration being used.

Pressed for time? See the Lemur docker file on `Github <https://github.com/Netflix/lemur-docker>`_.


Dependencies
------------

Some basic prerequisites which you'll need in order to run Lemur:

* A UNIX-based operating system (we test on Ubuntu, develop on OS X)
* Python 3.7 or greater
* PostgreSQL 9.4 or greater
* Nginx

.. note:: Lemur was built with in AWS in mind. This means that things such as databases (RDS), mail (SES), and TLS (ELB), are largely handled for us.  Lemur does **not** require AWS to function. Our guides and documentation try to be as generic as possible and are not intended to document every step of launching Lemur into a given environment.


Installing Build Dependencies
-----------------------------

If installing Lemur on a bare Ubuntu OS you will need to grab the following packages so that Lemur can correctly build its dependencies:

.. code-block:: bash

    sudo apt-get update
    sudo apt-get install nodejs nodejs-legacy python-pip python-dev python3-dev libpq-dev build-essential libssl-dev libffi-dev libsasl2-dev libldap2-dev nginx git supervisor npm postgresql

.. note:: PostgreSQL is only required if your database is going to be on the same host as the webserver.  npm is needed if you're installing Lemur from the source (e.g., from git).

.. note:: Installing node from a package manager may create the nodejs bin at  /usr/bin/nodejs instead of /usr/bin/node If that is the case run the following
    sudo ln -s /user/bin/nodejs /usr/bin/node

Now, install Python ``virtualenv`` package:

.. code-block:: bash

    sudo pip install -U virtualenv


Setting up an Environment
-------------------------

In this guide, Lemur will be installed in ``/www``, so you need to create that structure first:

.. code-block:: bash

    sudo mkdir /www
    cd /www

Clone Lemur inside the just created directory and give yourself write permission (we assume ``lemur`` is the user):

.. code-block:: bash

    sudo useradd lemur
    sudo passwd lemur
    sudo mkdir /home/lemur
    sudo chown lemur:lemur /home/lemur
    sudo git clone https://github.com/Netflix/lemur
    sudo chown -R lemur lemur/

Create the virtual environment, activate it and enter the Lemur's directory:

.. code-block:: bash

    su lemur
    virtualenv -p python3 lemur
    source /www/lemur/bin/activate
    cd lemur

.. note:: Activating the environment adjusts your PATH, so that things like pip now install into the virtualenv by default.


Installing from Source
~~~~~~~~~~~~~~~~~~~~~~

Once your system is prepared, ensure that you are in the virtualenv:

.. code-block:: bash

  which python

And then run:

.. code-block:: bash

  make release

.. note:: This command will install npm dependencies as well as compile static assets.


You may also run with the urlContextPath variable set. If this is set it will add the desired context path for subsequent calls back to lemur. This will only edit the front end code for calls back to the server, you will have to make sure the server knows about these routes.
::

  Example:
    urlContextPath=lemur
    /api/1/auth/providers -> /lemur/api/1/auth/providers

.. code-block:: bash

  make release urlContextPath={desired context path}


Creating a configuration
------------------------

Before we run Lemur, we must create a valid configuration file for it.  The Lemur command line interface comes with a simple command to get you up and running quickly.

Simply run:

.. code-block:: bash

  lemur create_config

.. note:: This command will create a default configuration under ``~/.lemur/lemur.conf.py`` you can specify this location by passing the ``config_path`` parameter to the ``create_config`` command.

You can specify ``-c`` or ``--config`` to any Lemur command to specify the current environment you are working in. Lemur will also look under the environmental variable ``LEMUR_CONF`` should that be easier to set up in your environment.


Update your configuration
-------------------------

Once created, you will need to update the configuration file with information about your environment, such as which database to talk to, where keys are stored etc.

.. code-block:: bash

    vi ~/.lemur/lemur.conf.py

.. note:: If you are unfamiliar with the SQLALCHEMY_DATABASE_URI string it can be broken up like so:
      ``postgresql://userame:password@<database-fqdn>:<database-port>/<database-name>``

Before Lemur will run you need to fill in a few required variables in the configuration file:

.. code-block:: bash

    LEMUR_SECURITY_TEAM_EMAIL
    #/the e-mail address needs to be enclosed in quotes
    LEMUR_DEFAULT_COUNTRY
    LEMUR_DEFAULT_STATE
    LEMUR_DEFAULT_LOCATION
    LEMUR_DEFAULT_ORGANIZATION
    LEMUR_DEFAULT_ORGANIZATIONAL_UNIT

Set Up Postgres
--------------

For production, a dedicated database is recommended, for this guide we will assume postgres has been installed and is on the same machine that Lemur is installed on.

First, set a password for the postgres user.  For this guide, we will use ``lemur`` as an example but you should use the database password generated by Lemur:

.. code-block:: bash

    sudo -u postgres -i
    psql
    postgres=# CREATE USER lemur WITH PASSWORD 'lemur';

Once successful, type CTRL-D to exit the Postgres shell.

Next, we will create our new database:

.. code-block:: bash

    sudo -u postgres createdb lemur

.. _InitializingLemur:

.. note::
    For this guide we assume you will use the `postgres` user to connect to your database, when deploying to a VM or container this is often all you will need. If you have a shared database it is recommend you give Lemur its own user.

.. note::
    Postgres 9.4 or greater is required as Lemur relies advanced data columns (e.g. JSON Column type)

Initializing Lemur
------------------

Lemur provides a helpful command that will initialize your database for you. It creates a default user (``lemur``) that is used by Lemur to help associate certificates that do not currently have an owner. This is most commonly the case when Lemur has discovered certificates from a third party source.  This is also a default user that can be used to administer Lemur.

In addition to creating a new user, Lemur also creates a few default email notifications.  These notifications are based on a few configuration options such as ``LEMUR_SECURITY_TEAM_EMAIL``.  They basically guarantee that every certificate within Lemur will send one expiration notification to the security team.

Your database installation requires the pg_trgm extension. If you do not have this installed already, you can allow the script to install this for you by adding the SUPERUSER permission to the lemur database user.

.. code-block:: bash
    sudo -u postgres -i
    psql
    postgres=# ALTER USER lemur WITH SUPERUSER

Additional notifications can be created through the UI or API.  See :ref:`Creating Notifications <CreatingNotifications>` and :ref:`Command Line Interface <CommandLineInterface>` for details.

**Make note of the password used as this will be used during first login to the Lemur UI.**

.. code-block:: bash

    cd /www/lemur/lemur
    lemur init

.. note:: If you added the SUPERUSER permission to the lemur database user above, it is recommended you revoke that permission now.

.. code-block:: bash
    sudo -u postgres -i
    psql
    postgres=# ALTER USER lemur WITH NOSUPERUSER


.. note:: It is recommended that once the ``lemur`` user is created that you create individual users for every day access.  There is currently no way for a user to self enroll for Lemur access, they must have an administrator create an account for them or be enrolled automatically through SSO.  This can be done through the CLI or UI.  See :ref:`Creating Users <CreatingUsers>` and :ref:`Command Line Interface <CommandLineInterface>` for details.

Set Up a Reverse Proxy
---------------------

By default, Lemur runs on port 8000.  Even if you change this, under normal conditions you won't be able to bind to port 80. To get around this (and to avoid running Lemur as a privileged user, which you shouldn't), we need to set up a simple web proxy. There are many different web servers you can use for this, we like and recommend Nginx.


Proxying with Nginx
~~~~~~~~~~~~~~~~~~~

You'll use the builtin ``HttpProxyModule`` within Nginx to handle proxying.  Edit the ``/etc/nginx/sites-available/default`` file according to the lines below

::

   location /api {
        proxy_pass  http://127.0.0.1:8000;
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

.. note:: See :doc:`../production/index` for more details on using Nginx.

After making these changes, restart Nginx service to apply them:

.. code-block:: bash

    sudo service nginx restart


Starting the Web Service
------------------------

Lemur provides a built-in web server (powered by gunicorn and eventlet) to get you off the ground quickly.

To start the web server, you simply use ``lemur start``. If you opted to use an alternative configuration path
you can pass that via the ``--config`` option.

.. note::
    You can login with the default user created during :ref:`Initializing Lemur <InitializingLemur>` or any other
    user you may have created.

::

  # Lemur's server runs on port 8000 by default. Make sure your client reflects
  # the correct host and port!
  lemur --config=/etc/lemur.conf.py start -b 127.0.0.1:8000

You should now be able to test the web service by visiting ``http://localhost:8000/``.


Running Lemur as a Service
--------------------------

We recommend using whatever software you are most familiar with for managing Lemur processes.  One option is `Supervisor <http://supervisord.org/>`_.


Configure ``supervisord``
~~~~~~~~~~~~~~~~~~~~~~~~~

Configuring Supervisor couldn't be more simple. Just point it to the ``lemur`` executable in your virtualenv's ``bin/`` folder and you're good to go.

::

  [program:lemur-web]
  directory=/www/lemur/
  command=/www/lemur/bin/lemur start
  autostart=true
  autorestart=true
  redirect_stderr=true
  stdout_logfile=syslog
  stderr_logfile=syslog

See :ref:`Using Supervisor <UsingSupervisor>` for more details on using Supervisor.


Syncing
-------

Lemur uses periodic sync tasks to make sure it is up-to-date with its environment. Things change outside of Lemur we do our best to reconcile those changes. The recommended method is to use CRON:

.. code-block:: bash

  crontab -e
  */15 * * * * lemur sync -s all
  0 22 * * * lemur check_revoked
  0 22 * * * lemur notify


Additional Utilities
--------------------

If you're familiar with Python you'll quickly find yourself at home, and even more so if you've used Flask.  The ``lemur`` command is just a simple wrapper around Flask's ``manage.py``, which means you get all of the power and flexibility that goes with it.

Some of the features which you'll likely find useful are listed below.


lock
~~~~

Encrypts sensitive key material - this is most useful for storing encrypted secrets in source code.


unlock
~~~~~~

Decrypts sensitive key material - used to decrypt the secrets stored in source during deployment.


Automated celery tasks
~~~~~~~~~~~~~~~~~~~~~~

Please refer to :ref:`Periodic Tasks <PeriodicTasks>` to learn more about task scheduling in Lemur.


What's Next?
------------

Get familiar with how Lemur works by reviewing the :doc:`../guide/index`. When you're ready see :doc:`../production/index` for more details on how to configure Lemur for production.

The above just gets you going, but for production there are several different security considerations to take into account.  Remember, Lemur is handling sensitive data and security is imperative.
