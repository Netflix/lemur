Frequently Asked Questions
==========================

Common Problems
---------------

In my startup logs I see *'Aborting... Lemur cannot locate db encryption key, is LEMUR_ENCRYPTION_KEYS set?'*
  You likely have not correctly configured **LEMUR_ENCRYPTION_KEYS**. See
  :doc:`administration` for more information.


I am seeing Lemur's javascript load in my browser but not the CSS.
  Ensure that you are placing *include mime.types;* to your Nginx static file location. See
  :doc:`production/index` for example configurations.


After installing Lemur I am unable to login
  Ensure that you are trying to login with the credentials you entered during `lemur init`. These are separate
  from the postgres database credentials.


Running 'lemur db upgrade' seems stuck.
  Most likely, the upgrade is stuck because an existing query on the database is holding onto a lock that the
  migration needs.

  To resolve, login to your lemur database and run:

    SELECT * FROM pg_locks l INNER JOIN pg_stat_activity s ON (l.pid = s.pid) WHERE waiting AND NOT granted;

  This will give you a list of queries that are currently waiting to be executed. From there attempt to idenity the PID
  of the query blocking the migration. Once found execute:

    select pg_terminate_backend(<blocking-pid>);

  See `<http://stackoverflow.com/questions/22896496/alembic-migration-stuck-with-postgresql>`_ for more.


How do I
--------

... script the Lemur installation to bootstrap things like roles and users?
  Lemur is a simple Flask (Python) application that runs using a utility
  runner. A script that creates a project and default user might look something
  like this:

  .. code-block:: python

     # Bootstrap the Flask environment
     from flask import current_app

     from lemur.users.service import create as create_user
     from lemur.roles.service import create as create_role
     from lemur.accounts.service import create as create_account

     role = create_role('aRole', 'this is a new role')
     create_user('admin', 'password', 'lemur@nobody', True, [role]
