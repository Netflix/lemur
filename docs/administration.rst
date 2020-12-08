Configuration
=============

.. warning::
    There are many secrets that Lemur uses that must be protected. All of these options are set via the Lemur configuration
    file. It is highly advised that you do not store your secrets in this file! Lemur provides functions
    that allow you to encrypt files at rest and decrypt them when it's time for deployment. See :ref:`Credential Management <CredentialManagement>`
    for more information.

.. note::
    All configuration values are python strings unless otherwise noted.


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

.. data:: LOG_UPGRADE_FILE
    :noindex:

    ::

        LOG_UPGRADE_FILE = "/logs/lemur/db_upgrade.log"

.. data:: DEBUG
    :noindex:

    Sets the flask debug flag to true (if supported by the webserver)

    ::

        DEBUG = False

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


.. data:: SQLALCHEMY_POOL_SIZE
    :noindex:

            The default connection pool size is 5 for sqlalchemy managed connections.   Depending on the number of Lemur instances,
            please specify per instance connection pool size.  Below is an example to set connection pool size to 10.

        ::

        SQLALCHEMY_POOL_SIZE = 10


    .. warning::
This is an optional setting but important to review and set for optimal database connection usage and for overall database performance.

.. data:: SQLALCHEMY_MAX_OVERFLOW
    :noindex:

        This setting allows to create connections in addition to specified number of connections in pool size.   By default, sqlalchemy
        allows 10 connections to create in addition to the pool size.  This is also an optional setting.  If `SQLALCHEMY_POOL_SIZE` and
        `SQLALCHEMY_MAX_OVERFLOW` are not speficied then each Lemur instance may create maximum of 15 connections.

    ::

        SQLALCHECK_MAX_OVERFLOW = 0


    .. note::
Specifying the `SQLALCHEMY_MAX_OVERFLOW` to 0 will enforce limit to not create connections above specified pool size.


.. data:: LEMUR_ALLOW_WEEKEND_EXPIRATION
    :noindex:

        Specifies whether to allow certificates created by Lemur to expire on weekends. Default is True.

.. data:: LEMUR_ALLOWED_DOMAINS
    :noindex:

        List of regular expressions for domain restrictions; if the list is not empty, normal users can only issue
        certificates for domain names matching at least one pattern on this list. Administrators are exempt from this
        restriction.

        Cerificate common name is matched against these rules *if* it does not contain a space. SubjectAltName DNS names
        are always matched against these rules.

        Take care to write patterns in such way to not allow the `*` wildcard character inadvertently. To match a `.`
        character, it must be escaped (as `\.`).

.. data:: LEMUR_OWNER_EMAIL_IN_SUBJECT
    :noindex:

        By default, Lemur will add the certificate owner's email address to certificate subject (for CAs that allow it).
        Set this to `False` to disable this.

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


.. data:: PUBLIC_CA_MAX_VALIDITY_DAYS
    :noindex:
        Use this config to override the limit of 397 days of validity for certificates issued by CA/Browser compliant authorities.
        The authorities with cab_compliant option set to true will use this config. The example below overrides the default validity
        of 397 days and sets it to 365 days.

    ::

        PUBLIC_CA_MAX_VALIDITY_DAYS = 365


.. data:: DEFAULT_VALIDITY_DAYS
    :noindex:
        Use this config to override the default validity of 365 days for certificates offered through Lemur UI. Any CA which
        is not CA/Browser Forum compliant will be using this value as default validity to be displayed on UI. Please
        note that this config is used for cert issuance only through Lemur UI. The example below overrides the default validity
        of 365 days and sets it to 1095 days (3 years).

    ::

        DEFAULT_VALIDITY_DAYS = 1095


.. data:: DEBUG_DUMP
    :noindex:

        Dump all imported or generated CSR and certificate details to stdout using OpenSSL. (default: `False`)

.. data:: ALLOW_CERT_DELETION
    :noindex:

        When set to True, certificates can be marked as deleted via the API and deleted certificates will not be displayed
        in the UI. When set to False (the default), the certificate delete API will always return "405 method not allowed"
        and deleted certificates will always be visible in the UI. (default: `False`)


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

        LEMUR_DEFAULT_ORGANIZATIONAL_UNIT = ""


.. data:: LEMUR_DEFAULT_ISSUER_PLUGIN
    :noindex:

    ::

        LEMUR_DEFAULT_ISSUER_PLUGIN = "verisign-issuer"


.. data:: LEMUR_DEFAULT_AUTHORITY
    :noindex:

    ::

        LEMUR_DEFAULT_AUTHORITY = "verisign"


.. _NotificationOptions:

Notification Options
--------------------

Lemur supports a small variety of notification types through a set of notification plugins.
By default, Lemur configures a standard set of email notifications for all certificates.

**Plugin-capable notifications**

These notifications can be configured to use all available notification plugins.

Supported types:

* Certificate expiration

**Email-only notifications**

These notifications can only be sent via email and cannot use other notification plugins.

Supported types:

* CA certificate expiration
* Pending ACME certificate failure
* Certificate rotation

**Default notifications**

When a certificate is created, the following email notifications are created for it if they do not exist.
If these notifications already exist, they will be associated with the new certificate.

* ``DEFAULT_<OWNER>_X_DAY``, where X is the set of values specified in ``LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS`` and defaults to 30, 15, and 2 if not specified. The owner's username will replace ``<OWNER>``.
* ``DEFAULT_SECURITY_X_DAY``, where X is the set of values specified in ``LEMUR_SECURITY_TEAM_EMAIL_INTERVALS`` and defaults to ``LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS`` if not specified (which also defaults to 30, 15, and 2 if not specified).

These notifications can be disabled if desired. They can also be unassociated with a specific certificate.

**Disabling notifications**

Notifications can be disabled either for an individual certificate (which disables all notifications for that certificate)
or for an individual notification object (which disables that notification for all associated certificates).
At present, disabling a notification object will only disable certificate expiration notifications, and not other types,
since other notification types don't use notification objects.

**Certificate expiration**

Certificate expiration notifications are sent when the scheduled task to send certificate expiration notifications runs
(see :ref:`PeriodicTasks`). Specific patterns of certificate names may be excluded using ``--exclude`` (when using
cron; you may specify this multiple times for multiple patterns) or via the config option ``EXCLUDE_CN_FROM_NOTIFICATION``
(when using celery; this is a list configuration option, meaning you specify multiple values, such as
``['exclude', 'also exclude']``). The specified exclude pattern will match if found anywhere in the certificate name.

When the periodic task runs, Lemur checks for certificates meeting the following conditions:

* Certificate has notifications enabled
* Certificate is not expired
* Certificate is not revoked
* Certificate name does not match the `exclude` parameter
* Certificate has at least one associated notification object
* That notification is active
* That notification's configured interval and unit match the certificate's remaining lifespan

All eligible certificates are then grouped by owner and applicable notification. For each notification and certificate group,
Lemur will send the expiration notification using whichever plugin was configured for that notification object.
In addition, Lemur will send an email to the certificate owner and security team (as specified by the
``LEMUR_SECURITY_TEAM_EMAIL`` configuration parameter).

**CA certificate expiration**

Certificate authority certificate expiration notifications are sent when the scheduled task to send authority certificate
expiration notifications runs (see :ref:`PeriodicTasks`). Notifications are sent via the intervals configured in the
configuration parameter ``LEMUR_AUTHORITY_CERT_EXPIRATION_EMAIL_INTERVALS``, with a default of 365 and 180 days.

When the periodic task runs, Lemur checks for certificates meeting the following conditions:

* Certificate has notifications enabled
* Certificate is not expired
* Certificate is not revoked
* Certificate is associated with a CA
* Certificate's remaining lifespan matches one of the configured intervals

All eligible certificates are then grouped by owner and expiration interval. For each interval and certificate group,
Lemur will send the CA certificate expiration notification via email to the certificate owner and security team
(as specified by the ``LEMUR_SECURITY_TEAM_EMAIL`` configuration parameter).

**Pending ACME certificate failure**

Whenever a pending ACME certificate fails to be issued, Lemur will send a notification via email to the certificate owner
and security team (as specified by the ``LEMUR_SECURITY_TEAM_EMAIL`` configuration parameter). This email is not sent if
the pending certificate had notifications disabled.

**Certificate rotation**

Whenever a cert is rotated, Lemur will send a notification via email to the certificate owner. This notification is
disabled by default; to enable it, you must set the option ``--notify`` (when using cron) or the configuration parameter
``ENABLE_ROTATION_NOTIFICATION`` (when using celery).

**Email notifications**

Templates for emails are located under `lemur/plugins/lemur_email/templates` and can be modified for your needs.

The following configuration options are supported:

.. data:: LEMUR_EMAIL_SENDER
    :noindex:

    Specifies which service will be delivering notification emails. Valid values are `SMTP` or `SES`

    .. note::
        If using SMTP as your provider you will need to define additional configuration options as specified by Flask-Mail.
        See: `Flask-Mail <https://pythonhosted.org/Flask-Mail>`_

        If you are using SES the email specified by the `LEMUR_MAIL` configuration will need to be verified by AWS before
        you can send any mail. See: `Verifying Email Address in Amazon SES <http://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-email-addresses.html>`_


.. data:: LEMUR_SES_SOURCE_ARN
    :noindex:

    Specifies an ARN to use as the SourceArn when sending emails via SES.

    .. note::
        This parameter is only required if you're using a sending authorization with SES.
        See: `Using sending authorization with Amazon SES <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html>`_


.. data:: LEMUR_SES_REGION
    :noindex:

    Specifies a region for sending emails via SES.

    .. note::
        This parameter defaults to us-east-1 and is only required if you wish to use a different region.


.. data:: LEMUR_EMAIL
    :noindex:

        Lemur sender's email

        ::

            LEMUR_EMAIL = 'lemur@example.com'


.. data:: LEMUR_SECURITY_TEAM_EMAIL
    :noindex:

        This is an email or list of emails that should be notified when a certificate is expiring. It is also the contact email address for any discovered certificate.

        ::

            LEMUR_SECURITY_TEAM_EMAIL = ['security@example.com']

.. data:: LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS
    :noindex:

        Lemur notification intervals. If unspecified, the value [30, 15, 2] is used.

        ::

            LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS = [30, 15, 2]

.. data:: LEMUR_SECURITY_TEAM_EMAIL_INTERVALS
    :noindex:

       Alternate notification interval set for security team notifications. Use this if you would like the default security team notification interval for new certificates to differ from the global default as specified in LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS. If unspecified, the value of LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS is used. Security team default notifications for new certificates can effectively be disabled by setting this value to an empty array.

       ::

          LEMUR_SECURITY_TEAM_EMAIL_INTERVALS = [15, 2]

.. data:: LEMUR_AUTHORITY_CERT_EXPIRATION_EMAIL_INTERVALS
    :noindex:

       Notification interval set for CA certificate expiration notifications. If unspecified, the value [365, 180] is used (roughly one year and 6 months).

       ::

          LEMUR_AUTHORITY_CERT_EXPIRATION_EMAIL_INTERVALS = [365, 180]


Celery Options
---------------
To make use of automated tasks within lemur (e.g. syncing source/destinations, or reissuing ACME certificates), you
need to configure celery. See :ref:`Periodic Tasks <PeriodicTasks>` for more in depth documentation.

.. data:: CELERY_RESULT_BACKEND
    :noindex:

        The url to your redis backend (needs to be in the format `redis://<host>:<port>/<database>`)

.. data:: CELERY_BROKER_URL
    :noindex:

        The url to your redis broker (needs to be in the format `redis://<host>:<port>/<database>`)

.. data:: CELERY_IMPORTS
    :noindex:

        The module that celery needs to import, in our case thats `lemur.common.celery`

.. data:: CELERY_TIMEZONE
    :noindex:

        The timezone for celery to work with


.. data:: CELERYBEAT_SCHEDULE
    :noindex:

        This defines the schedule, with which the celery beat makes the worker run the specified tasks.

Since the celery module, relies on the RedisHandler, the following options also need to be set.

.. data:: REDIS_HOST
    :noindex:

        Hostname of your redis instance

.. data:: REDIS_PORT
    :noindex:

        Port on which redis is running (default: 6379)

.. data:: REDIS_DB
    :noindex:

        Which redis database to be used, by default redis offers databases 0-15 (default: 0)

Authentication Options
----------------------
Lemur currently supports Basic Authentication, LDAP Authentication, Ping OAuth2, and Google out of the box. Additional flows can be added relatively easily.

LDAP Options
~~~~~~~~~~~~

Lemur supports the use of an LDAP server in conjunction with Basic Authentication. Lemur local users can still be defined and take precedence over LDAP users. If a local user does not exist, LDAP will be queried for authentication. Only simple ldap binding with or without TLS is supported.

LDAP support requires the pyldap python library, which also depends on the following openldap packages.

.. code-block:: bash

      $ sudo apt-get update
      $ sudo apt-get install libldap2-dev libsasl2-dev libldap2-dev libssl-dev


To configure the use of an LDAP server, a number of settings need to be configured in `lemur.conf.py`.

Here is an example LDAP configuration stanza you can add to your config. Adjust to suit your environment of course.

.. code-block:: python

        LDAP_AUTH = True
        LDAP_BIND_URI='ldaps://secure.evilcorp.net'
        LDAP_BASE_DN='DC=users,DC=evilcorp,DC=net'
        LDAP_EMAIL_DOMAIN='evilcorp.net'
        LDAP_USE_TLS = True
        LDAP_CACERT_FILE = '/opt/lemur/trusted.pem'
        LDAP_REQUIRED_GROUP = 'certificate-management-access'
        LDAP_GROUPS_TO_ROLES = {'certificate-management-admin': 'admin', 'certificate-management-read-only': 'read-only'}
        LDAP_IS_ACTIVE_DIRECTORY = True


The lemur ldap module uses the `user principal name` (upn) of the authenticating user to bind. This is done once for each user at login time. The UPN is effectively the email address in AD/LDAP of the user. If the user doesn't provide the email address, it constructs one based on the username supplied (which should normally match the samAccountName) and the value provided by the config LDAP_EMAIL_DOMAIN.
The config LDAP_BASE_DN tells lemur where to search within the AD/LDAP tree for the given UPN (user). If the bind with those credentials is successful - there is a valid user in AD with correct password.

Each of the LDAP options are described below.

.. data:: LDAP_AUTH
    :noindex:

        This enables the use of LDAP

        ::

            LDAP_AUTH = True

.. data:: LDAP_BIND_URI
    :noindex:

        Specifies the LDAP server connection string

        ::

            LDAP_BIND_URI = 'ldaps://hostname'

.. data:: LDAP_BASE_DN
    :noindex:

        Specifies the LDAP distinguished name location to search for users

        ::

            LDAP_BASE_DN = 'DC=Users,DC=Evilcorp,DC=com'

.. data:: LDAP_EMAIL_DOMAIN
    :noindex:

        The email domain used by users in your directory. This is used to build the userPrincipalName to search with.

        ::

            LDAP_EMAIL_DOMAIN = 'evilcorp.com'

The following LDAP options are not required, however TLS is always recommended.

.. data:: LDAP_USE_TLS
    :noindex:

        Enables the use of TLS when connecting to the LDAP server. Ensure the LDAP_BIND_URI is using ldaps scheme.

        ::

            LDAP_USE_TLS = True

.. data:: LDAP_CACERT_FILE
    :noindex:

        Specify a Certificate Authority file containing PEM encoded trusted issuer certificates. This can be used if your LDAP server is using certificates issued by a private CA.

        ::

            LDAP_CACERT_FILE = '/path/to/cacert/file'

.. data:: LDAP_REQUIRED_GROUP
    :noindex:

        Lemur has pretty open permissions. You can define an LDAP group to specify who can access Lemur. Only members of this group will be able to login.

        ::

            LDAP_REQUIRED_GROUP = 'Lemur LDAP Group Name'

.. data:: LDAP_GROUPS_TO_ROLES
    :noindex:

        You can also define a dictionary of ldap groups mapped to lemur roles. This allows you to use ldap groups to manage access to owner/creator roles in Lemur

        ::

            LDAP_GROUPS_TO_ROLES = {'lemur_admins': 'admin', 'Lemur Team DL Group': 'team@example.com'}


.. data:: LDAP_IS_ACTIVE_DIRECTORY
    :noindex:

        When set to True, nested group memberships are supported, by searching for groups with the member:1.2.840.113556.1.4.1941 attribute set to the user DN.
        When set to False, the list of groups will be determined by the 'memberof' attribute of the LDAP user logging in.

        ::

            LDAP_IS_ACTIVE_DIRECTORY = False


Authentication Providers
~~~~~~~~~~~~~~~~~~~~~~~~

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

.. data:: OAUTH2_VERIFY_CERT
    :noindex:

        ::

            OAUTH2_VERIFY_CERT = True

.. data:: GOOGLE_CLIENT_ID
    :noindex:

        ::

            GOOGLE_CLIENT_ID = "client-id"

.. data:: GOOGLE_SECRET
    :noindex:

        ::

            GOOGLE_SECRET = "somethingsecret"


Metric Providers
~~~~~~~~~~~~~~~~

If you are not using a metric provider you do not need to configure any of these options.

.. data:: ACTIVE_PROVIDERS
    :noindex:

        A list of metric plugins slugs to be ativated.

        ::

            METRIC_PROVIDERS = ['atlas-metric']


Plugin Specific Options
-----------------------

ACME Plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. data:: ACME_DNS_PROVIDER_TYPES
    :noindex:

        Dictionary of ACME DNS Providers and their requirements.

.. data:: ACME_ENABLE_DELEGATED_CNAME
    :noindex:

        Enables delegated DNS domain validation using CNAMES.  When enabled, Lemur will attempt to follow CNAME records to authoritative DNS servers when creating DNS-01 challenges.


Active Directory Certificate Services Plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


.. data:: ADCS_SERVER
    :noindex:

        FQDN of your ADCS Server


.. data:: ADCS_AUTH_METHOD
    :noindex:

        The chosen authentication method. Either ‘basic’ (the default), ‘ntlm’ or ‘cert’ (SSL client certificate). The next 2 variables are interpreted differently for different methods.


.. data:: ADCS_USER
    :noindex:

        The username (basic) or the path to the public cert (cert) of the user accessing PKI


.. data:: ADCS_PWD
    :noindex:

        The passwd (basic) or the path to the private key (cert) of the user accessing PKI


.. data:: ADCS_TEMPLATE
    :noindex:

        Template to be used for certificate issuing. Usually display name w/o spaces
        
.. data:: ADCS_TEMPLATE_<upper(authority.name)>
    :noindex:

        If there is a config variable ADCS_TEMPLATE_<upper(authority.name)> take the value as Cert template else default to ADCS_TEMPLATE to be compatible with former versions. Template to be used for certificate issuing. Usually display name w/o spaces

.. data:: ADCS_START
    :noindex:
        Used in ADCS-Sourceplugin. Minimum id of the first certificate to be returned. ID is increased by one until ADCS_STOP. Missing cert-IDs are ignored

.. data:: ADCS_STOP
    :noindex:
        Used for ADCS-Sourceplugin. Maximum id of the certificates returned. 
        

.. data:: ADCS_ISSUING
    :noindex:

        Contains the issuing cert of the CA


.. data:: ADCS_ROOT
    :noindex:

        Contains the root cert of the CA

Entrust Plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Enables the creation of Entrust certificates. You need to set the API access up with Entrust support. Check the information in the Entrust Portal as well. 
Certificates are created as "SERVER_AND_CLIENT_AUTH".
Caution: Sometimes the entrust API does not respond in a timely manner. This error is handled and reported by the plugin. Should this happen you just have to hit the create button again after to create a valid certificate. 
The following parameters have to be set in the configuration files.

.. data:: ENTRUST_URL
    :noindex:
    
       This is the url for the Entrust API. Refer to the API documentation.
       
.. data:: ENTRUST_API_CERT
    :noindex:
    
       Path to the certificate file in PEM format. This certificate is created in the onboarding process. Refer to the API documentation.
       
.. data:: ENTRUST_API_KEY
    :noindex:
    
       Path to the key file in RSA format. This certificate is created in the onboarding process. Refer to the API documentation. Caution: the request library cannot handle encrypted keys. The keyfile therefore has to contain the unencrypted key. Please put this in a secure location on the server.
       
.. data:: ENTRUST_API_USER
    :noindex:
    
       String with the API user. This user is created in the onboarding process. Refer to the API documentation.   
       
.. data:: ENTRUST_API_PASS
    :noindex:
    
       String with the password for the API user. This password is created in the onboarding process. Refer to the API documentation.

.. data:: ENTRUST_NAME
    :noindex:
    
        String with the name that should appear as certificate owner in the Entrust portal. Refer to the API documentation.

.. data:: ENTRUST_EMAIL
    :noindex:
    
        String with the email address that should appear as certificate contact email in the Entrust portal. Refer to the API documentation.       

.. data:: ENTRUST_PHONE
    :noindex:
    
        String with the phone number that should appear as certificate contact in the Entrust portal. Refer to the API documentation.        

.. data:: ENTRUST_ISSUING
    :noindex:
    
        Contains the issuing cert of the CA

.. data:: ENTRUST_ROOT
    :noindex:
    
        Contains the root cert of the CA

.. data:: ENTRUST_PRODUCT_<upper(authority.name)>
    :noindex:

        If there is a config variable ENTRUST_PRODUCT_<upper(authority.name)> take the value as cert product name else default to "STANDARD_SSL". Refer to the API documentation for valid products names.

Verisign Issuer Plugin
~~~~~~~~~~~~~~~~~~~~~~

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

            This is the url for the Digicert API (e.g. https://www.digicert.com)


.. data:: DIGICERT_ORDER_TYPE
    :noindex:

            This is the type of certificate to order. (e.g. ssl_plus, ssl_ev_plus see: https://www.digicert.com/services/v2/documentation/order/overview-submit)


.. data:: DIGICERT_API_KEY
    :noindex:

            This is the Digicert API key


.. data:: DIGICERT_ORG_ID
    :noindex:

            This is the Digicert organization ID tied to your API key


.. data:: DIGICERT_ROOT
    :noindex:

            This is the root to be used for your CA chain


.. data:: DIGICERT_DEFAULT_VALIDITY_DAYS
    :noindex:

            This is the default validity (in days), if no end date is specified. (Default: 397)


.. data:: DIGICERT_MAX_VALIDITY_DAYS
    :noindex:

            This is the maximum validity (in days). (Default: value of DIGICERT_DEFAULT_VALIDITY_DAYS)


.. data:: DIGICERT_PRIVATE
    :noindex:

            This is whether or not to issue a private certificate. (Default: False)


CFSSL Issuer Plugin
~~~~~~~~~~~~~~~~~~~

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

.. data:: CFSSL_KEY
    :noindex:

        This is the hmac key to authenticate to the CFSSL service. (Optional)


Hashicorp Vault Source/Destination Plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Lemur can import and export certificate data to and from a Hashicorp Vault secrets store. Lemur can connect to a different Vault service per source/destination.

.. note:: This plugin does not supersede or overlap the 3rd party Vault Issuer plugin.

.. note:: Vault does not have any configuration properties however it does read from a file on disk for a vault access token. The Lemur service account needs read access to this file.

Vault Source
""""""""""""

The Vault Source Plugin will read from one Vault object location per source defined. There is expected to be one or more certificates defined in each object in Vault.

Vault Destination
"""""""""""""""""

A Vault destination can be one object in Vault or a directory where all certificates will be stored as their own object by CN.

Vault Destination supports a regex filter to prevent certificates with SAN that do not match the regex filter from being deployed. This is an optional feature per destination defined.


AWS Source/Destination Plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

PowerDNS ACME Plugin
~~~~~~~~~~~~~~~~~~~~~~

The following configuration properties are required to use the PowerDNS ACME Plugin for domain validation.


.. data:: ACME_POWERDNS_DOMAIN
    :noindex:

            This is the FQDN for the PowerDNS API (without path)


.. data:: ACME_POWERDNS_SERVERID
    :noindex:

            This is the ServerID attribute of the PowerDNS API Server (i.e. "localhost")


.. data:: ACME_POWERDNS_APIKEYNAME
    :noindex:

            This is the Key name to use for authentication (i.e. "X-API-Key")


.. data:: ACME_POWERDNS_APIKEY
    :noindex:

            This is the API Key to use for authentication (i.e. "Password")


.. data:: ACME_POWERDNS_RETRIES
    :noindex:

            This is the number of times DNS Verification should be attempted (i.e. 20)


.. data:: ACME_POWERDNS_VERIFY
    :noindex:

            This configures how TLS certificates on the PowerDNS API target are validated.  The PowerDNS Plugin depends on the PyPi requests library, which supports the following options for the verify parameter:

            True: Verifies the TLS certificate was issued by a known publicly-trusted CA. (Default)

            False: Disables certificate validation (Not Recommended)

            File/Dir path to CA Bundle: Verifies the TLS certificate was issued by a Certificate Authority in the provided CA bundle.

ACME Plugin
~~~~~~~~~~~~

The following configration properties are optional for the ACME plugin to use. They allow reusing an existing ACME
account. See :ref:`Using a pre-existing ACME account <AcmeAccountReuse>` for more details.


.. data:: ACME_PRIVATE_KEY
    :noindex:

            This is the private key, the account was registered with (in JWK format)

.. data:: ACME_REGR
    :noindex:

            This is the registration for the ACME account, the most important part is the uri attribute (in JSON)

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


.. data:: acme

    Handles all ACME related tasks, like ACME plugin testing.

    ::

        lemur acme


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
    Internally, this uses `Alembic <http://alembic.zzzcomputing.com/en/latest/>`_ to manage database migrations.

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
    Kevin Glisson <kglisson@netflix.com>,
    Curtis Castrapel <ccastrapel@netflix.com>,
    Hossein Shafagh <hshafagh@netflix.com>
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
    Curtis Castrapel <ccastrapel@netflix.com>,
    Hossein Shafagh <hshafagh@netflix.com>,
    Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>,
    Chad Sine <csine@netflix.com>
:Type:
    Issuer
:Description:
    Adds support for the ACME protocol (including LetsEncrypt) with domain validation using several providers.


Atlas
-----

:Authors:
    Kevin Glisson <kglisson@netflix.com>,
    Curtis Castrapel <ccastrapel@netflix.com>,
    Hossein Shafagh <hshafagh@netflix.com>
:Type:
    Metric
:Description:
    Adds basic support for the `Atlas <https://github.com/Netflix/atlas/wiki>`_ telemetry system.


Email
-----

:Authors:
    Kevin Glisson <kglisson@netflix.com>,
    Curtis Castrapel <ccastrapel@netflix.com>,
    Hossein Shafagh <hshafagh@netflix.com>
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


AWS (Source)
----

:Authors:
    Kevin Glisson <kglisson@netflix.com>,
    Curtis Castrapel <ccastrapel@netflix.com>,
    Hossein Shafagh <hshafagh@netflix.com>
:Type:
    Source
:Description:
    Uses AWS IAM as a source of certificates to manage. Supports a multi-account deployment.


AWS (Destination)
----

:Authors:
    Kevin Glisson <kglisson@netflix.com>,
    Curtis Castrapel <ccastrapel@netflix.com>,
    Hossein Shafagh <hshafagh@netflix.com>
:Type:
    Destination
:Description:
    Uses AWS IAM as a destination for Lemur generated certificates. Support a multi-account deployment.


AWS (SNS Notification)
-----

:Authors:
    Jasmine Schladen <jschladen@netflix.com>
:Type:
    Notification
:Description:
    Adds support for SNS notifications. SNS notifications (like other notification plugins) are currently only supported
    for certificate expiration. Configuration requires a region, account number, and SNS topic name; these elements
    are then combined to build the topic ARN. Lemur must have access to publish messages to the specified SNS topic.


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

Vault
-----

:Authors:
    Christopher Jolley <chris@alwaysjolley.com>
:Type:
    Source
:Description:
    Source plugin imports certificates from Hashicorp Vault secret store.

Vault
-----

:Authors:
    Christopher Jolley <chris@alwaysjolley.com>
:Type:
    Destination
:Description:
    Destination plugin to deploy certificates to Hashicorp Vault secret store.


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


InfluxDB
--------

:Authors:
    Titouan Christophe
:Type:
    Metric
:Description:
    Sends key metrics to InfluxDB
:Links:
    https://github.com/titouanc/lemur-influxdb

Hashicorp Vault
---------------

:Authors:
    Ron Cohen
:Type:
    Issuer
:Description:
    Adds support for basic Vault PKI secret backend.
:Links:
    https://github.com/RcRonco/lemur_vault


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
