Configuration
=============

.. warning::
    There are many secrets that Lemur uses that must be protected. All of these options are set via the Lemur configuration
    file. It is highly advised that you do not store your secrets in this file! Lemur provides functions
    that allow you to encrypt files at rest and decrypt them when it's time for deployment. See :ref:`Credential Management <CredentialManagement>`
    for more information.

Basic Configuration
-------------------

.. data:: LOG_LEVEL
    :noindex:

    ::

        LOG_LEVEL = "DEBUG"

.. data:: LOG_FILE
    :noindex:

    ::

        LOG_FILE = "/logs/lemur/lemur-test.log"

.. data:: debug
    :noindex:

    Sets the flask debug flag to true (if supported by the webserver)

    ::

        debug = False

    .. warning::
        This should never be used in a production environment as it exposes Lemur to
        remote code execution through the debug console.


.. data:: CORS
    :noindex:

    Allows for cross domain requests, this is most commonly used for development but could
    be use in production if you decided to host the webUI on a different domain than the server.

    Use this cautiously, if you're not sure. Set it to `False`

    ::

        CORS = False


.. data:: SQLALCHEMY_DATABASE_URI
    :noindex:

        If you have ever used sqlalchemy before this is the standard connection string used. Lemur uses a postgres database and the connection string would look something like:

    ::

        SQLALCHEMY_DATABASE_URI = 'postgresql://<user>:<password>@<hostname>:5432/lemur'


.. data:: LEMUR_ALLOW_WEEKEND_EXPIRATION
    :noindex:

        Specifies whether to allow certificates created by Lemur to expire on weekends. Default is True.

.. data:: LEMUR_RESTRICTED_DOMAINS
    :noindex:

        This allows the administrator to mark a subset of domains or domains matching a particular regex as
        *restricted*. This means that only an administrator is allows to issue the domains in question.

.. data:: LEMUR_TOKEN_SECRET
    :noindex:

        The TOKEN_SECRET is the secret used to create JWT tokens that are given out to users. This should be securely generated and kept private.

    ::

        LEMUR_TOKEN_SECRET = 'supersecret'

    An example of how you might generate a random string:

        >>> import random
        >>> secret_key = ''.join(random.choice(string.ascii_uppercase) for x in range(6))
        >>> secret_key = secret_key + ''.join(random.choice("~!@#$%^&*()_+") for x in range(6))
        >>> secret_key = secret_key + ''.join(random.choice(string.ascii_lowercase) for x in range(6))
        >>> secret_key = secret_key + ''.join(random.choice(string.digits) for x in range(6))


.. data:: LEMUR_ENCRYPTION_KEYS
    :noindex:

        The LEMUR_ENCRYPTION_KEYS is used to encrypt data at rest within Lemur's database. Without a key Lemur will refuse
        to start. Multiple keys can be provided to facilitate key rotation. The first key in the list is used for
        encryption and all keys are tried for decryption until one works. Each key must be 32 URL safe base-64 encoded bytes.

        Running lemur create_config will securely generate a key for your configuration file.
        If you would like to generate your own, we recommend the following method:

            >>> import os
            >>> import base64
            >>> base64.urlsafe_b64encode(os.urandom(32))

    ::

        LEMUR_ENCRYPTION_KEYS = ['1YeftooSbxCiX2zo8m1lXtpvQjy27smZcUUaGmffhMY=', 'LAfQt6yrkLqOK5lwpvQcT4jf2zdeTQJV1uYeh9coT5s=']


Certificate Default Options
---------------------------

Lemur allows you to fine tune your certificates to your organization. The following defaults are presented in the UI
and are used when Lemur creates the CSR for your certificates.


.. data:: LEMUR_DEFAULT_COUNTRY
    :noindex:

    ::

        LEMUR_DEFAULT_COUNTRY = "US"


.. data:: LEMUR_DEFAULT_STATE
    :noindex:

    ::

        LEMUR_DEFAULT_STATE = "California"


.. data:: LEMUR_DEFAULT_LOCATION
    :noindex:

    ::

        LEMUR_DEFAULT_LOCATION = "Los Gatos"


.. data:: LEMUR_DEFAULT_ORGANIZATION
    :noindex:

    ::

        LEMUR_DEFAULT_ORGANIZATION = "Netflix"


.. data:: LEMUR_DEFAULT_ORGANIZATIONAL_UNIT
    :noindex:

    ::

        LEMUR_DEFAULT_ORGANIZATIONAL_UNIT = "Operations"


.. data:: LEMUR_DEFAULT_ISSUER_PLUGIN
    :noindex:

    ::

        LEMUR_DEFAULT_ISSUER_PLUGIN = "verisign-issuer"


.. data:: LEMUR_DEFAULT_AUTHORITY
    :noindex:

    ::

        LEMUR_DEFAULT_AUTHORITY = "verisign"


Notification Options
--------------------

Lemur currently has very basic support for notifications. Currently only expiration notifications are supported. Actual notification
is handled by the notification plugins that you have configured. Lemur ships with the 'Email' notification that allows expiration emails
to be sent to subscribers.

Templates for expiration emails are located under `lemur/plugins/lemur_email/templates` and can be modified for your needs.
Notifications are sent to the certificate creator, owner and security team as specified by the `LEMUR_SECURITY_TEAM_EMAIL` configuration parameter.

Certificates marked as inactive will **not** be notified of upcoming expiration. This enables a user to essentially
silence the expiration. If a certificate is active and is expiring the above will be notified according to the `LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS` or
30, 15, 2 days before expiration if no intervals are set.

Lemur supports sending certification expiration notifications through SES and SMTP.


.. data:: LEMUR_EMAIL_SENDER
    :noindex:

    Specifies which service will be delivering notification emails. Valid values are `SMTP` or `SES`

    .. note::
        If using SMTP as your provider you will need to define additional configuration options as specified by Flask-Mail.
        See: `Flask-Mail <https://pythonhosted.org/Flask-Mail>`_

        If you are using SES the email specified by the `LEMUR_MAIL` configuration will need to be verified by AWS before
        you can send any mail. See: `Verifying Email Address in Amazon SES <http://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-email-addresses.html>`_


.. data:: LEMUR_MAIL
    :noindex:

        Lemur sender's email

        ::

            LEMUR_MAIL = 'lemur.example.com'


.. data:: LEMUR_SECURITY_TEAM_EMAIL
    :noindex:

        This is an email or list of emails that should be notified when a certificate is expiring. It is also the contact email address for any discovered certificate.

        ::

            LEMUR_SECURITY_TEAM_EMAIL = ['security@example.com']


.. data:: LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS
    :noindex:

        Lemur notification intervals

        ::

            LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS = [30, 15, 2]


Authentication Options
----------------------
Lemur currently supports Basic Authentication, Ping OAuth2, and Google out of the box. Additional flows can be added relatively easily.
If you are not using an authentication provider you do not need to configure any of these options.

For more information about how to use social logins, see: `Satellizer <https://github.com/sahat/satellizer>`_

.. data:: ACTIVE_PROVIDERS
    :noindex:

        ::

            ACTIVE_PROVIDERS = ["ping", "google", "oauth2"]

.. data:: PING_SECRET
    :noindex:

        ::

            PING_SECRET = 'somethingsecret'

.. data:: PING_ACCESS_TOKEN_URL
    :noindex:

        ::

            PING_ACCESS_TOKEN_URL = "https://<yourpingserver>/as/token.oauth2"


.. data:: PING_USER_API_URL
    :noindex:

        ::

            PING_USER_API_URL = "https://<yourpingserver>/idp/userinfo.openid"

.. data:: PING_JWKS_URL
    :noindex:

        ::

            PING_JWKS_URL = "https://<yourpingserver>/pf/JWKS"

.. data:: PING_NAME
    :noindex:

        ::

            PING_NAME = "Example Oauth2 Provider"

.. data:: PING_CLIENT_ID
    :noindex:

        ::

            PING_CLIENT_ID = "client-id"

.. data:: PING_REDIRECT_URI
    :noindex:

        ::

            PING_REDIRECT_URI = "https://<yourlemurserver>/api/1/auth/ping"

.. data:: PING_AUTH_ENDPOINT
    :noindex:

        ::

            PING_AUTH_ENDPOINT = "https://<yourpingserver>/oauth2/authorize"

.. data:: OAUTH2_SECRET
    :noindex:

        ::

            OAUTH2_SECRET = 'somethingsecret'

.. data:: OAUTH2_ACCESS_TOKEN_URL
    :noindex:

        ::

            OAUTH2_ACCESS_TOKEN_URL = "https://<youroauthserver> /oauth2/v1/authorize"


.. data:: OAUTH2_USER_API_URL
    :noindex:

        ::

            OAUTH2_USER_API_URL = "https://<youroauthserver>/oauth2/v1/userinfo"

.. data:: OAUTH2_JWKS_URL
    :noindex:

        ::

            OAUTH2_JWKS_URL = "https://<youroauthserver>/oauth2/v1/keys"

.. data:: OAUTH2_NAME
    :noindex:

        ::

            OAUTH2_NAME = "Example Oauth2 Provider"

.. data:: OAUTH2_CLIENT_ID
    :noindex:

        ::

            OAUTH2_CLIENT_ID = "client-id"

.. data:: OAUTH2_REDIRECT_URI
    :noindex:

        ::

            OAUTH2_REDIRECT_URI = "https://<yourlemurserver>/api/1/auth/oauth2"

.. data:: OAUTH2_AUTH_ENDPOINT
    :noindex:

        ::

            OAUTH2_AUTH_ENDPOINT = "https://<youroauthserver>/oauth2/v1/authorize"

.. data:: GOOGLE_CLIENT_ID
    :noindex:

        ::

            GOOGLE_CLIENT_ID = "client-id"

.. data:: GOOGLE_SECRET
    :noindex:

        ::

            GOOGLE_SECRET = "somethingsecret"


Plugin Specific Options
-----------------------

Verisign Issuer Plugin
^^^^^^^^^^^^^^^^^^^^^^

Authorities will each have their own configuration options. There is currently just one plugin bundled with Lemur,
Verisign/Symantec. Additional plugins may define additional options. Refer to the plugin's own documentation
for those plugins.

.. data:: VERISIGN_URL
    :noindex:

        This is the url for the Verisign API


.. data:: VERISIGN_PEM_PATH
    :noindex:

        This is the path to the mutual TLS certificate used for communicating with Verisign


.. data:: VERISIGN_FIRST_NAME
    :noindex:

        This is the first name to be used when requesting the certificate


.. data:: VERISIGN_LAST_NAME
    :noindex:

        This is the last name to be used when requesting the certificate

.. data:: VERISIGN_EMAIL
    :noindex:

        This is the email to be used when requesting the certificate


.. data:: VERISIGN_INTERMEDIATE
    :noindex:

        This is the intermediate to be used for your CA chain


.. data:: VERISIGN_ROOT
    :noindex:

        This is the root to be used for your CA chain


Digicert Issuer Plugin
~~~~~~~~~~~~~~~~~~~~~~

The following configuration properties are required to use the Digicert issuer plugin.


.. data:: DIGICERT_URL
    :noindex:

            This is the url for the Digicert API


.. data:: DIGICERT_API_KEY
    :noindex:

            This is the Digicert API key


.. data:: DIGICERT_ORG_ID
    :noindex:

            This is the Digicert organization ID tied to your API key


.. data:: DIGICERT_INTERMEDIATE
    :noindex:

            This is the intermediate to be used for your CA chain


.. data:: DIGICERT_ROOT
    :noindex:

            This is the root to be used for your CA chain


.. data:: DIGICERT_DEFAULT_VALIDITY
    :noindex:

            This is the default validity (in years), if no end date is specified. (Default: 1)



CFSSL Issuer Plugin
^^^^^^^^^^^^^^^^^^^

The following configuration properties are required to use the CFSSL issuer plugin.

.. data:: CFSSL_URL
    :noindex:

        This is the URL for the CFSSL API

.. data:: CFSSL_ROOT
    :noindex:

        This is the root to be used for your CA chain

.. data:: CFSSL_INTERMEDIATE
    :noindex:

        This is the intermediate to be used for your CA chain


AWS Source/Destination Plugin
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In order for Lemur to manage its own account and other accounts we must ensure it has the correct AWS permissions.

.. note:: AWS usage is completely optional. Lemur can upload, find and manage TLS certificates in AWS. But is not required to do so.

Setting up IAM roles
""""""""""""""""""""

Lemur's AWS plugin uses boto heavily to talk to all the AWS resources it manages. By default it uses the on-instance credentials to make the necessary calls.

In order to limit the permissions, we will create two new IAM roles for Lemur. You can name them whatever you would like but for example sake we will be calling them LemurInstanceProfile and Lemur.

Lemur uses to STS to talk to different accounts. For managing one account this isn't necessary but we will still use it so that we can easily add new accounts.

LemurInstanceProfile is the IAM role you will launch your instance with. It actually has almost no rights. In fact it should really only be able to use STS to assume role to the Lemur role.

Here are example policies for the LemurInstanceProfile:

SES-SendEmail

.. code-block:: python

    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "ses:SendEmail"
          ],
          "Resource": "*"
        }
      ]
    }


STS-AssumeRole

.. code-block:: python

    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action":
            "sts:AssumeRole",
          "Resource": "*"
        }
      ]
    }



Next we will create the Lemur IAM role.

.. note::

    The default IAM role that Lemur assumes into is called `Lemur`, if you need to change this ensure you set `LEMUR_INSTANCE_PROFILE` to your role name in the configuration.


Here is an example policy for Lemur:

IAM-ServerCertificate

.. code-block:: python

    {
        "Statement": [
                    {
                         "Action": [
                              "iam:ListServerCertificates",
                              "iam:UpdateServerCertificate",
                              "iam:GetServerCertificate",
                              "iam:UploadServerCertificate"
                         ],
                         "Resource": [
                              "*"
                         ],
                         "Effect": "Allow",
                         "Sid": "Stmt1404836868000"
                    }
               ]
    }


.. code-block:: python

    {
        "Statement": [
                    {
                         "Action": [
                              "elasticloadbalancing:DescribeInstanceHealth",
                              "elasticloadbalancing:DescribeLoadBalancerAttributes",
                              "elasticloadbalancing:DescribeLoadBalancerPolicyTypes",
                              "elasticloadbalancing:DescribeLoadBalancerPolicies",
                              "elasticloadbalancing:DescribeLoadBalancers",
                              "elasticloadbalancing:DeleteLoadBalancerListeners",
                              "elasticloadbalancing:CreateLoadBalancerListeners"
                         ],
                         "Resource": [
                              "*"
                         ],
                         "Effect": "Allow",
                         "Sid": "Stmt1404841912000"
                    }
               ]
    }


Setting up STS access
"""""""""""""""""""""

Once we have setup our accounts we need to ensure that we create a trust relationship so that LemurInstanceProfile can assume the Lemur role.

In the AWS console select the Lemur IAM role and select the Trust Relationships tab and click Edit Trust Relationship

Below is an example policy:

.. code-block:: python

    {
      "Version": "2008-10-17",
      "Statement": [
        {
          "Sid": "",
          "Effect": "Allow",
          "Principal": {
            "AWS": [
              "arn:aws:iam::<awsaccountnumber>:role/LemurInstanceProfile",
            ]
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }


Adding N+1 accounts
"""""""""""""""""""

To add another account we go to the new account and create a new Lemur IAM role with the same policy as above.

Then we would go to the account that Lemur is running is and edit the trust relationship policy.

An example policy:

.. code-block:: python

    {
      "Version": "2008-10-17",
      "Statement": [
        {
          "Sid": "",
          "Effect": "Allow",
          "Principal": {
            "AWS": [
              "arn:aws:iam::<awsaccountnumber>:role/LemurInstanceProfile",
              "arn:aws:iam::<awsaccountnumber1>:role/LemurInstanceProfile",
            ]
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }

Setting up SES
""""""""""""""

Lemur has built in support for sending it's certificate notifications via Amazon's simple email service (SES). To force
Lemur to use SES ensure you are the running as the IAM role defined above and that you have followed the steps outlined
in Amazon's documentation `Setting up Amazon SES <http://docs.aws.amazon.com/ses/latest/DeveloperGuide/setting-up-ses.html>`_

The configuration::

    LEMUR_MAIL = 'lemur.example.com'

Will be the sender of all notifications, so ensure that it is verified with AWS.

SES if the default notification gateway and will be used unless SMTP settings are configured in the application configuration
settings.

.. _CommandLineInterface:

Command Line Interface
======================

Lemur installs a command line script under the name ``lemur``. This will allow you to
perform most required operations that are unachievable within the web UI.

If you're using a non-standard configuration location, you'll need to prefix every command with
--config (excluding create_config, which is a special case). For example::

    lemur --config=/etc/lemur.conf.py help

For a list of commands, you can also use ``lemur help``, or ``lemur [command] --help``
for help on a specific command.

.. note:: The script is powered by a library called `Flask-Script <https://github.com/smurfix/flask-script>`_

Builtin Commands
----------------

All commands default to `~/.lemur/lemur.conf.py` if a configuration is not specified.

.. data:: create_config

    Creates a default configuration file for Lemur.

    Path defaults to ``~/.lemur/lemur.config.py``

    ::

        lemur create_config .

    .. note::
        This command is a special case and does not depend on the configuration file
        being set.


.. data:: init

    Initializes the configuration file for Lemur.

    ::

        lemur -c /etc/lemur.conf.py init


.. data:: start

    Starts a Lemur service. You can also pass any flag that Gunicorn uses to specify the webserver configuration.

    ::

        lemur start -w 6 -b 127.0.0.1:8080


.. data:: db upgrade

    Performs any needed database migrations.

    ::

        lemur db upgrade


.. data:: check_revoked

    Traverses every certificate that Lemur is aware of and attempts to understand its validity.
    It utilizes both OCSP and CRL. If Lemur is unable to come to a conclusion about a certificates
    validity its status is marked 'unknown'.


.. data:: sync

    Sync attempts to discover certificates in the environment that were not created by Lemur. If you wish to only sync
    a few sources you can pass a comma delimited list of sources to sync.

    ::

        lemur sync -s source1,source2


    Additionally you can also list the available sources that Lemur can sync.

    ::

        lemur sync


.. data:: notify

    Will traverse all current notifications and see if any of them need to be triggered.

    ::

        lemur notify


Sub-commands
------------

Lemur includes several sub-commands for interacting with Lemur such as creating new users, creating new roles and even
issuing certificates.

The best way to discover these commands is by using the built in help pages

    ::

        lemur --help


and to get help on sub-commands

    ::

        lemur certificates --help



Upgrading Lemur
===============

To upgrade Lemur to the newest release you will need to ensure you have the latest code and have run any needed
database migrations.

To get the latest code from github run

    ::

        cd <lemur-source-directory>
        git pull -t <version>
        python setup.py develop


.. note::
    It's important to grab the latest release by specifying the release tag. This tags denote stable versions of Lemur.
    If you want to try the bleeding edge version of Lemur you can by using the master branch.


After you have the latest version of the Lemur code base you must run any needed database migrations. To run migrations

    ::

        cd <lemur-source-directory>/lemur
        lemur db upgrade


This will ensure that any needed tables or columns are created or destroyed.

.. note::
    Internally, this uses `Alembic <https://alembic.readthedocs.org/en/latest/>`_ to manage database migrations.

.. note::
    By default Alembic looks for the `migrations` folder in the current working directory.The migrations folder is
    located under `<LEMUR_HOME>/lemur/migrations` if you are running the lemur command from any location besides
    `<LEMUR_HOME>/lemur` you will need to pass the `-d` flag to specify the absolute file path to the `migrations` folder.

Plugins
=======

There are several interfaces currently available to extend Lemur. These are a work in
progress and the API is not frozen.

Lemur includes several plugins by default. Including extensive support for AWS, VeriSign/Symantec.

Verisign/Symantec
-----------------

:Authors:
    Kevin Glisson <kglisson@netflix.com>
:Type:
    Issuer
:Description:
    Basic support for the VICE 2.0 API


Cryptography
------------

:Authors:
    Kevin Glisson <kglisson@netflix.com>,
    Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>
:Type:
    Issuer
:Description:
    Toy certificate authority that creates self-signed certificate authorities.
    Allows for the creation of arbitrary authorities and end-entity certificates.
    This is *not* recommended for production use.


Acme
----

:Authors:
    Kevin Glisson <kglisson@netflix.com>,
    Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>
:Type:
    Issuer
:Description:
    Adds support for the ACME protocol (including LetsEncrypt) with domain validation being handled Route53.


Atlas
-----

:Authors:
    Kevin Glisson <kglisson@netflix.com>
:Type:
    Metric
:Description:
    Adds basic support for the `Atlas <https://github.com/Netflix/atlas/wiki>`_ telemetry system.


Email
-----

:Authors:
    Kevin Glisson <kglisson@netflix.com>
:Type:
    Notification
:Description:
    Adds support for basic email notifications via SES.


Slack
-----

:Authors:
    Harm Weites <harm@weites.com>
:Type:
    Notification
:Description:
    Adds support for slack notifications.


AWS
----

:Authors:
    Kevin Glisson <kglisson@netflix.com>
:Type:
    Source
:Description:
    Uses AWS IAM as a source of certificates to manage. Supports a multi-account deployment.


AWS
----

:Authors:
    Kevin Glisson <kglisson@netflix.com>
:Type:
    Destination
:Description:
    Uses AWS IAM as a destination for Lemur generated certificates. Support a multi-account deployment.


Kubernetes
----------

:Authors:
    Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>
:Type:
    Destination
:Description:
    Allows Lemur to upload generated certificates to the Kubernetes certificate store.


Java
----

:Authors:
    Kevin Glisson <kglisson@netflix.com>
:Type:
    Export
:Description:
    Generates java compatible .jks keystores and truststores from Lemur managed certificates.


Openssl
-------

:Authors:
    Kevin Glisson <kglisson@netflix.com>
:Type:
    Export
:Description:
    Leverages Openssl to support additional export formats (pkcs12)


CFSSL
-----

:Authors:
    Charles Hendrie <chad.hendrie@thomsonreuters.com>
:Type:
    Issuer
:Description:
    Basic support for generating certificates from the private certificate authority CFSSL


3rd Party Plugins
=================

The following plugins are available and maintained by members of the Lemur community:

Digicert
--------

:Authors:
    Chris Dorros
:Type:
    Issuer
:Description:
    Adds support for basic Digicert
:Links:
    https://github.com/opendns/lemur-digicert


Have an extension that should be listed here? Submit a `pull request <https://github.com/netflix/lemur>`_ and we'll
get it added.

Want to create your own extension? See :doc:`../developer/plugins/index` to get started.


Identity and Access Management
==============================

Lemur uses a Role Based Access Control (RBAC) mechanism to control which users have access to which resources. When a
user is first created in Lemur they can be assigned one or more roles. These roles are typically dynamically created
depending on an external identity provider (Google, LDAP, etc.), or are hardcoded within Lemur and associated with special
meaning.

Within Lemur there are three main permissions: AdminPermission, CreatorPermission, OwnerPermission. Sub-permissions such
as ViewPrivateKeyPermission are compositions of these three main Permissions.

Lets take a look at how these permissions are used:

Each `Authority` has a set of roles associated with it. If a user is also associated with the same roles
that the `Authority` is associated with, Lemur allows that user to user/view/update that `Authority`.

This RBAC is also used when determining which users can access which certificate private key. Lemur's current permission
structure is setup such that if the user is a `Creator` or `Owner` of a given certificate they are allow to view that
private key. Owners can also be a role name, such that any user with the same role as owner will be allowed to view the
private key information.

These permissions are applied to the user upon login and refreshed on every request.

.. seealso::

    `Flask-Principal <https://pythonhosted.org/Flask-Principal>`_
