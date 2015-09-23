Frequently Asked Questions
==========================

Common Problems
---------------

In my startup logs I see *'Aborting... Lemur cannot locate db encryption key, is LEMUR_ENCRYPTION_KEY set?'*
  You likely have not correctly configured **LEMUR_ENCRYPTION_KEY**. See
  :doc:`administration/index` for more information.


I am seeing Lemur's javascript load in my browser but not the CSS.
  Ensure that you are placing *include mime.types;* to your Nginx static file location. See
  :doc:`production/index` for example configurations.


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
