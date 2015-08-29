Configuration
=============

.. warning::
    There are many secrets that Lemur uses that must be protected. All of these options are set via the Lemur configruation
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


.. data:: SQLACHEMY_DATABASE_URI
    :noindex:

        If you have ever used sqlalchemy before this is the standard connection string used. Lemur uses a postgres database and the connection string would look something like:

    ::

        SQLALCHEMY_DATABASE_URI = 'postgresql://<user>:<password>@<hostname>:5432/lemur'


.. data:: LEMUR_RESTRICTED_DOMAINS
    :noindex:

        This allows the administrator to mark a subset of domains or domains matching a particular regex as
        *restricted*. This means that only an administrator is allows to issue the domains in question.

.. data:: LEMUR_TOKEN_SECRET
    :noindex:

        The TOKEN_SECRET is the secret used to create JWT tokens that are given out to users. This should be securely generated and be kept private.

        See `SECRET_KEY` for methods on secure secret generation.

    ::

        LEMUR_TOKEN_SECRET = 'supersecret'

    An example of how you might generate a random string:

        >>> import random
        >>> secret_key = ''.join(random.choice(string.ascii_uppercase) for x in range(6))
        >>> secret_key = secret_key + ''.join(random.choice("~!@#$%^&*()_+") for x in range(6))
        >>> secret_key = secret_key + ''.join(random.choice(string.ascii_lowercase) for x in range(6))
        >>> secret_key = secret_key + ''.join(random.choice(string.digits) for x in range(6))


.. data:: LEMUR_ENCRYPTION_KEY
    :noindex:

        The LEMUR_ENCRYPTION_KEY is used to encrypt data at rest within Lemur's database. Without this key Lemur will refuse
        to start.

        See `LEMUR_TOKEN_SECRET` for methods of secure secret generation.

    ::

        LEMUR_ENCRYPTION_KEY = 'supersupersecret'


Certificate Default Options
---------------------------

Lemur allows you to find tune your certificates to your organization. The following defaults are presented in the UI
and are used when Lemur creates the CSR for your certificates.


.. data:: LEMUR_DEFAULT_COUNTRY
    :noindex:

    ::

        LEMUR_DEFAULT_COUNTRY = "US"


.. data:: LEMUR_DEFAULT_STATE
    :noindex:

    ::

        LEMUR_DEFAULT_STATE = "CA"


.. data:: LEMUR_DEFAULT_LOCATION
    :noindex:

    ::

        LEMUR_DEFAULT_LOCATION = "Los Gatos"


.. data:: LEMUR_DEFAULT_ORGANIZATION
    :noindex:

    ::

        LEMUR_DEFAULT_ORGANIZATION = "Netflix"


.. data:: LEMUR_DEFAULT_ORGANIZATION_UNIT
    :noindex:

    ::

        LEMUR_DEFAULT_ORGANIZATIONAL_UNIT = "Operations"


Notification Options
--------------------

Lemur currently has very basic support for notifications. Notifications are sent to the certificate creator, owner and
security team as specified by the `SECURITY_TEAM_EMAIL` configuration parameter.

The template for all of these notifications lives under lemur/template/event.html and can be easily modified to fit your
needs.

Certificates marked as in-active will **not** be notified of upcoming expiration. This enables a user to essentially
silence the expiration. If a certificate is active and is expiring the above will be notified at 30, 15, 5, 2 days
respectively.

Lemur supports sending certification expiration notifications through SES and SMTP.


.. data:: LEMUR_EMAIL_SENDER
    :noindex:

            Specifies which service will be delivering notification emails. Valid values are `SMTP` or `SES`

.. note::
    If using STMP as your provider you will need to define additional configuration options as specified by Flask-Mail.
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


Authority Options
-----------------

Authorities will each have their own configuration options. There are currently two plugins bundled with Lemur,
Verisign/Symantec and CloudCA

.. data:: VERISIGN_URL
    :noindex:

        This is the url for the verisign API


.. data:: VERISIGN_PEM_PATH
    :noindex:

        This is the path to the mutual SSL certificate used for communicating with Verisign


.. data:: CLOUDCA_URL
    :noindex:

        This is the URL for CLoudCA API


.. data:: CLOUDCA_PEM_PATH
    :noindex:

        This is the path to the mutual SSL Certificate use for communicating with CLOUDCA

.. data:: CLOUDCA_BUNDLE
    :noindex:

        This is the path to the CLOUDCA certificate bundle

Authentication
--------------
Lemur currently supports Basic Authentication and Ping OAuth2 out of the box, additional flows can be added relatively easily
If you are not using Ping you do not need to configure any of these options.

For more information about how to use social logins, see: `Satellizer <https://github.com/sahat/satellizer>`_

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



AWS Plugin Configuration
========================

In order for Lemur to manage it's own account and other accounts we must ensure it has the correct AWS permissions.

.. note:: AWS usage is completely optional. Lemur can upload, find and manage SSL certificates in AWS. But is not required to do so.

Setting up IAM roles
--------------------

Lemur's aws plugin uses boto heavily to talk to all the AWS resources it manages. By default it uses the on-instance credentials to make the necessary calls.

In order to limit the permissions we will create a new two IAM roles for Lemur. You can name them whatever you would like but for example sake we will be calling them LemurInstanceProfile and Lemur.

Lemur uses to STS to talk to different accounts. For managing one account this isn't necessary but we will still use it so that we can easily add new accounts.

LemurInstanceProfile is the IAM role you will launch your instance with. It actually has almost no rights. In fact it should really only be able to use STS to assume role to the Lemur role.

Here is are example polices for the LemurInstanceProfile:

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



Next we will create the the Lemur IAM role. Lemur

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
---------------------
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
-------------------

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
--------------

Lemur has built in support for sending it's certificate notifications via Amazon's simple email service (SES). To force
Lemur to use SES ensure you are the running as the IAM role defined above and that you have followed the steps outlined
in Amazon's documentation `Setting up Amazon SES <http://docs.aws.amazon.com/ses/latest/DeveloperGuide/setting-up-ses.html>`_

The configuration::

    LEMUR_MAIL = 'lemur.example.com'

Will be sender of all notifications, so ensure that it is verified with AWS.

SES if the default notification gateway and will be used unless SMTP settings are configured in the application configuration
settings.

Upgrading Lemur
===============

Lemur provides an easy way to upgrade between versions. Simply download the newest
version of Lemur from pypi and then apply any schema cahnges with the following command.

.. code-block:: bash

    $ lemur db upgrade

.. note:: Internally, this uses `Alembic <https://alembic.readthedocs.org/en/latest/>`_ to manage database migrations.

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


.. data:: create_user

    Creates new users within Lemur.

    ::

        lemur create_user -u jim -e jim@example.com


.. data:: create_role

    Creates new roles within Lemur.

    ::

        lemur create_role -n example -d "a new role"


.. data:: check_revoked

    Traverses every certificate that Lemur is aware of and attempts to understand it's validity.
    It utilizes both OCSP and CRL. If Lemur is unable to come to a conclusion about a certificates
    validity it's status is marked 'unknown'


.. data:: sync

    Sync attempts to discover certificates in the environment that were not created by Lemur. If you wish to only sync
    a few sources you can pass a comma delimited list of sources to sync

    ::

        lemur sync source1,source2


    Additionally you can also list the available sources that Lemur can sync

    ::

        lemur sync -list


Identity and Access Management
==============================

Lemur uses a Role Based Access Control (RBAC) mechanism to control which users have access to which resources. When a
user is first created in Lemur the can be assigned one or more roles. These roles are typically dynamically created
depending on a external identity provider (Google, LDAP, etc.,) or are hardcoded within Lemur and associated with special
meaning.

Within Lemur there are three main permissions: AdminPermission, CreatorPermission, OwnerPermission. Sub-permissions such
as ViewPrivateKeyPermission are compositions of these three main Permissions.

Lets take a look at how these permissions used:

Each `Authority` has a set of roles associated with it. If a user is also associated with the same roles
that the `Authority` is associated with it Lemur allows that user to user/view/update that `Authority`.

This RBAC is also used when determining which users can access which certificate private key. Lemur's current permission
structure is setup such that if the user is a `Creator` or `Owner` of a given certificate they are allow to view that
private key.

These permissions are applied to the user upon login and refreshed on every request.

.. seealso::
    `Flask-Principal <https://pythonhosted.org/Flask-Principal>`_
