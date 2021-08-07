Several interfaces exist for extending Lemur:

* Issuer (lemur.plugins.base.issuer)
* Destination (lemur.plugins.base.destination)
* Source (lemur.plugins.base.source)
* Notification (lemur.plugins.base.notification)

Each interface has its own functions that will need to be defined in order for
your plugin to work correctly. See :ref:`Plugin Interfaces <PluginInterfaces>` for details.


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
    except Exception as e:
        VERSION = 'unknown'

Inside of ``plugin.py``, you'll declare your Plugin class::

    import lemur_pluginname
    from lemur.plugins.base.issuer import IssuerPlugin

    class PluginName(IssuerPlugin):
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

You can potentially package multiple plugin types in one package, say you want to create a source and
destination plugins for the same third-party. To accomplish this simply alias the plugin in entry points to point
at multiple plugins within your package::

    setup(
        # ...
        entry_points={
            'lemur.plugins': [
                'pluginnamesource = lemur_pluginname.plugin:PluginNameSource',
                'pluginnamedestination = lemur_pluginname.plugin:PluginNameDestination'
            ],
        },
    )

Once your plugin files are in place and the ``/www/lemur/setup.py`` file has been modified, you can load your plugin into your instance by reinstalling lemur:
::

    (lemur)$cd /www/lemur
    (lemur)$pip install -e .

That's it! Users will be able to install your plugin via ``pip install <package name>``.

.. SeeAlso:: For more information about python packages see `Python Packaging <https://packaging.python.org/en/latest/distributing.html>`_

.. SeeAlso:: For an example of a plugin operation outside of Lemur's core, see `lemur-digicert <https://github.com/opendns/lemur-digicert>`_

.. _PluginInterfaces:

Plugin Interfaces
=================

In order to use the interfaces all plugins are required to inherit and override unimplemented functions
of the parent object.

Issuer
------

Issuer plugins are used when you have an external service that creates certificates or authorities.
In the simple case the third party only issues certificates (Verisign, DigiCert, etc.).

If you have a third party or internal service that creates authorities (EJBCA, etc.), Lemur has you covered,
it can treat any issuer plugin as both a source of creating new certificates as well as new authorities.


The `IssuerPlugin` exposes four functions functions::

    def create_certificate(self, csr, issuer_options):
        # requests.get('a third party')
    def revoke_certificate(self, certificate, reason):
        # requests.put('a third party')
    def get_ordered_certificate(self, order_id):
        # requests.get('already existing certificate')
    def canceled_ordered_certificate(self, pending_cert, **kwargs):
        # requests.put('cancel an order that has yet to be issued')

Lemur will pass a dictionary of all possible options for certificate creation. Including a valid CSR, and the raw options associated with the request.

If you wish to be able to create new authorities implement the following function and ensure that the ROOT_CERTIFICATE and the INTERMEDIATE_CERTIFICATE (if any) for the new authority is returned::

    def create_authority(self, options):
        root_cert, intermediate_cert, username, password = request.get('a third party')

        # if your provider creates specific credentials for each authority you can associated them with the role associated with the authority
        # these credentials will be provided along with any other options when a certificate is created
        role = dict(username=username, password=password, name='generatedAuthority')
        return root_cert, intermediate_cert, [role]


.. Note::
    Lemur uses PEM formatted certificates as it's internal standard, if you receive certificates in other formats convert them to PEM before returning.


If instead you do not need need to generate authorities but instead use a static authority (Verisign, DigiCert), you can use publicly available constants::


    def create_authority(self, options):
        # optionally associate a role with authority to control who can use it
        role = dict(username='', password='', name='exampleAuthority')
        # username and password don't really matter here because we do no need to authenticate our authority against a third party
        return EXAMPLE_ROOT_CERTIFICATE, EXAMPLE_INTERMEDIATE_CERTIFICATE, [role]


.. Note:: You do not need to associate roles to the authority at creation time as they can always be associated after the fact.


The `IssuerPlugin` doesn't have any options like Destination, Source, and Notification plugins. Essentially Lemur **should** already have
any fields you might need to submit a request to a third party. If there are additional options you need
in your plugin feel free to open an issue, or look into adding additional options to issuers yourself.

**Asynchronous Certificates**
An issuer may take some time to actually issue a certificate for an order.  In this case, a `PendingCertificate` is returned, which holds information to recreate a `Certificate` object at a later time.  Then, `get_ordered_certificate()` should be run periodically via `python manage.py pending_certs fetch -i all` to attempt to retrieve an ordered certificate::

    def get_ordered_ceriticate(self, order_id):
        # order_id is the external id of the order, not the external_id of the certificate
        # retrieve an order, and check if there is an issued certificate attached to it

`cancel_ordered_certificate()` should be implemented to allow an ordered certificate to be canceled before it is issued::

        def cancel_ordered_certificate(self, pending_cert, **kwargs):
            # pending_cert should contain the necessary information to match an order
            # kwargs can be given to provide information to the issuer for canceling

Destination
-----------

Destination plugins allow you to propagate certificates managed by Lemur to additional third parties. This provides flexibility when
different orchestration systems have their own way of manage certificates or there is an existing system you wish to integrate with Lemur.

By default destination plugins have a private key requirement. If your plugin does not require a certificates private key mark `requires_key = False`
in the plugins base class like so::

    class MyDestinationPlugin(DestinationPlugin):
        requires_key = False

The DestinationPlugin requires only one function to be implemented::

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        # request.post('a third party')

Additionally the DestinationPlugin allows the plugin author to add additional options
that can be used to help define sub-destinations.

For example, if we look at the aws-destination plugin we can see that it defines an `accountNumber` option::

    from lemur.common.utils import check_validation

    options = [
        {
            'name': 'accountNumber',
            'type': 'int',
            'required': True,
            'validation': check_validation('/^[0-9]{12,12}$/'),
            'helpMessage': 'Must be a valid AWS account number!',
        }
    ]

By defining an `accountNumber` we can make this plugin handle many N number of AWS accounts instead of just one.

The schema for defining plugin options are pretty straightforward:

  - **Name**: name of the variable you wish to present the user, snake case (snakeCase) is preferred as Lemur
    will parse these and create pretty variable titles
  - **Type** there are currently four supported variable types
      - **Int** creates an html integer box for the user to enter integers into
      - **Str** creates a html text input box
      - **Boolean** creates a checkbox for the user to signify truthiness
      - **Select** creates a select box that gives the user a list of options
          - When used a `available` key must be provided with a list of selectable options
  - **Required** determines if this option is required, this **must be a boolean value**
  - **Validation** simple Python (re) and JavaScript regular expression used to give the user an indication if the input value is valid. Use `check_validation()` from `lemur.common.utils` to ensure your expression will compile successfully prior to use.
  - **HelpMessage** simple string that provides more detail about the option

.. Note::
    DestinationPlugin, NotificationPlugin and SourcePlugin all support the option
    schema outlined above.


Notification
------------

Lemur includes the ability to create Email notifications by **default**. These notifications
currently come in the form of expiration and rotation notices for all certificates, expiration notices for CA certificates,
and ACME certificate creation failure notices. Lemur periodically checks certificate expiration dates and
determines if a given certificate is eligible for notification. There are currently only two parameters used to
determine if a certificate is eligible; validity expiration (date the certificate is no longer valid) and the number
of days the current date (UTC) is from that expiration date.

Certificate expiration notifications can also be configured for Slack or AWS SNS. Other notifications are not configurable.
Notifications sent to a certificate owner and security team (`LEMUR_SECURITY_TEAM_EMAIL`) can currently only be sent via email.

There are currently two objects that are available for notification plugins. The first is `NotificationPlugin`, which is the base object for
any notification within Lemur. Currently the only supported notification type is a certificate expiration notification. If you
are trying to create a new notification type (audit, failed logins, etc.) this would be the object to base your plugin on.
You would also then need to build additional code to trigger the new notification type.

The second is `ExpirationNotificationPlugin`, which inherits from the `NotificationPlugin` object.
You will most likely want to base your plugin on this object if you want to add new channels for expiration notices (HipChat, Jira, etc.). It adds default options that are required by
all expiration notifications (interval, unit). This interface expects for the child to define the following function::

    def send(self, notification_type, message, targets, options, **kwargs):
        #  request.post("some alerting infrastructure")


Source
------

When building Lemur we realized that although it would be nice if every certificate went through Lemur to get issued, but this is not
always be the case. Oftentimes there are third parties that will issue certificates on your behalf and these can get deployed
to infrastructure without any interaction with Lemur. In an attempt to combat this and try to track every certificate, Lemur has a notion of
certificate **Sources**. Lemur will contact the source at periodic intervals and attempt to **sync** against the source. This means downloading or discovering any
certificate Lemur does not know about and adding the certificate to its inventory to be tracked and alerted on.

The `SourcePlugin` object has one default option of `pollRate`. This controls the number of seconds which to get new certificates.

.. warning::
    Lemur currently has a very basic polling system of running a cron job every 15min to see which source plugins need to be run. A lock file is generated to guarantee that
    only one sync is running at a time. It also means that the minimum resolution of a source plugin poll rate is effectively 15min. You can always specify a faster cron
    job if you need a higher resolution sync job.


The `SourcePlugin` object requires implementation of one function::

      def get_certificates(self, options, **kwargs):
          #  request.get("some source of certificates")


.. note::
    Oftentimes to facilitate code re-use it makes sense put source and destination plugins into one package.


Export
------

Formats, formats and more formats. That's the current PKI landscape. See the always relevant `xkcd <https://xkcd.com/927/>`_.
Thankfully Lemur supports the ability to output your certificates into whatever format you want. This integration comes by the way
of Export plugins. Support is still new and evolving, the goal of these plugins is to return raw data in a new format that
can then be used by any number of applications. Included in Lemur is the `JavaExportPlugin` which currently supports generating
a Java Key Store (JKS) file for use in Java based applications.


The `ExportPlugin` object requires the implementation of one function::

    def export(self, body, chain, key, options, **kwargs):
        # sys.call('openssl hokuspocus')
        # return "extension", passphrase, raw


.. note::
    Support of various formats sometimes relies on external tools system calls. Always be mindful of sanitizing any input to these calls.


Membership
----------
Membership plugin allows Lemur to learn and validate membership details from an external service. Currently the plugin is configured to
support 3 APIs::

    def does_principal_exist(self, principal_email):
        raise NotImplementedError

    def does_group_exist(self, group_email):
        # check if a group (Team DL) exists

    def retrieve_user_memberships(self, user_id):
        # get a list of groups a user belongs to


Custom TLS Provider
-------------------

Managing TLS at the enterprise scale could be hard and often organizations offer custom wrapper implementations. It could
be ideal to use those while making calls to internal services. The `TLSPlugin` would help to achieve this. It requires the
implementation of one function which creates a TLS session::

     def session(self, server_application):
        # return active session


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

   from lemur.tests.conftest import *  # noqa


Test Cases
----------

You can now inherit from Lemur's core test classes. These are Django-based and ensure the database and other basic utilities are in a clean state:

.. code-block:: python

    import pytest
    from lemur.tests.vectors import INTERNAL_CERTIFICATE_A_STR, INTERNAL_PRIVATE_KEY_A_STR

    def test_export_keystore(app):
        from lemur.plugins.base import plugins
        p = plugins.get('java-keystore-jks')
        options = [{'name': 'passphrase', 'value': 'test1234'}]
        with pytest.raises(Exception):
            p.export(INTERNAL_CERTIFICATE_A_STR, "", "", options)

        raw = p.export(INTERNAL_CERTIFICATE_A_STR, "", INTERNAL_PRIVATE_KEY_A_STR, options)
        assert raw != b""


Running Tests
-------------

Running tests follows the py.test standard. As long as your test files and methods are named appropriately (``test_filename.py`` and ``test_function()``) you can simply call out to py.test:

::

    $ py.test -v
    ============================== test session starts ==============================
    platform darwin -- Python 2.7.10, pytest-2.8.5, py-1.4.30, pluggy-0.3.1
    cachedir: .cache
    plugins: flask-0.10.0
    collected 346 items

    lemur/plugins/lemur_acme/tests/test_acme.py::test_get_certificates PASSED

    =========================== 1 passed in 0.35 seconds ============================


.. SeeAlso:: Lemur bundles several plugins that use the same interfaces mentioned above.
