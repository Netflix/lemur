Writing a Plugin
================

**The plugin interface is a work in progress.**

Several interfaces exist for extending Lemur:

* Issuers (lemur.issuers)

Structure
---------

A plugins layout generally looks like the following::

    setup.py
    lemur_pluginname/
    lemur_pluginname/__init__.py
    lemur_pluginname/plugin.py

The ``__init__.py`` file should contain no plugin logic, and at most, a VERSION = 'x.x.x' line. For example,
if you want to pull the version using pkg_resources (which is what we recommend), your file might contain::

    try:
        VERSION = __import__('pkg_resources') \
            .get_distribution(__name__).version
    except Exception, e:
        VERSION = 'unknown'

Inside of ``plugin.py``, you'll declare your Plugin class::

    import lemur_pluginname
    from lemur.common.services.issuers.plugins import Issuer

    class PluginName(Plugin):
        title = 'Plugin Name'
        slug = 'pluginname'
        description = 'My awesome plugin!'
        version = lemur_pluginname.VERSION

        author = 'Your Name'
        author_url = 'https://github.com/yourname/lemur_pluginname'

        def widget(self, request, group, **kwargs):
            return "<p>Absolutely useless widget</p>"

And you'll register it via ``entry_points`` in your ``setup.py``::

    setup(
        # ...
        entry_points={
           'lemur.plugins': [
                'pluginname = lemur_pluginname.issuers:PluginName'
            ],
        },
    )


That's it! Users will be able to install your plugin via ``pip install <package name>`` and configure it
via the web interface based on the hooks you enabled.


Permissions
===========

As described in the plugin interface, Lemur provides a suite of permissions.

In most cases, a admin (that is, if User.is_admin is ``True``), will be granted implicit permissions
on everything.

This page attempts to describe those permissions, and the contextual objects along with them.

.. data:: add_project

         Controls whether a user can create a new project.

         ::

            >>> has_perm('add_project', user)


Testing
=======

Lemur provides a basic py.test-based testing framework for extensions.

In a simple project, you'll need to do a few things to get it working:

setup.py
--------

Augment your setup.py to ensure at least the following:

.. code-block:: python

   setup(
       # ...
      install_requires=[
          'lemur',
      ]
   )


conftest.py
-----------

The ``conftest.py`` file is our main entry-point for py.test. We need to configure it to load the Lemur pytest configuration:

.. code-block:: python

   from __future__ import absolute_import

   pytest_plugins = [
       'lemur.utils.pytest'
   ]


Test Cases
----------

You can now inherit from Lemur's core test classes. These are Django-based and ensure the database and other basic utilities are in a clean state:

.. code-block:: python

   # test_myextension.py
   from __future__ import absolute_import

   from lemur.testutils import TestCase

   class MyExtensionTest(TestCase):
       def test_simple(self):
          assert 1 != 2


Running Tests
-------------

Running tests follows the py.test standard. As long as your test files and methods are named appropriately (``test_filename.py`` and ``test_function()``) you can simply call out to py.test:

::

    $ py.test -v
    ============================== test session starts ==============================
    platform darwin -- Python 2.7.9 -- py-1.4.26 -- pytest-2.6.4/python2.7
    plugins: django
    collected 1 items

    tests/test_myextension.py::MyExtensionTest::test_simple PASSED

    =========================== 1 passed in 0.35 seconds ============================


