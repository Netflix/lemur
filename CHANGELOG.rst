Changelog
=========

Unreleased
~~~~~~~~~~~~~~~~~~~~


1.3.0 - `2023-02-13`
~~~~~~~~~~~~~~~~~~~~
This release contains many dependency updates, and numerous added or improved features over the last year.

Some of the notable changes in this release are:
- Removal of AWS S3 destinations and the respetive resources via the UI
- No fine-grained authz for role global_cert_issuer
- De-activate endpoint (Entrust Plugin)
- Remove unsafe paginate method and replace with sort_and_page
- Move to github workflows for tests
- Detect duplicate certs
- Metrics for certificate expiry
- Sync source: handling idle/invalidated connection
- Sync endpoint: capture error and continue
- Domain-level fine-grained authz 
- Handle and report authz warmup exception
- Ensure secondary certificates are not removed when rotating AWS endpoints
- Improved metric around expired endpoints
- Change pkg_resources call in plugin loading to use resolve rather than load
- Log when an expiring deployed certificate is detected 
- NS1 DNS ACME Plugin
- Add a new endpoint that allows updating a certificate owner
- Support rotating endpoints with non-unique names via CLI
- Restrict multiple accounts on a certificate, by plugin
- Moving to dependabot's auto versioning strategy

Special thanks to all who contributed to this release, notably:

- `Neil Schelly <https://github.com/neilschelly>`_
- `Mitch Cail <https://github.com/mitchcail>`_
- `Bob Shannon <https://github.com/bobmshannon>`_
- `alwaysjolley <https://github.com/alwaysjolley>`_


1.2.0 - `2022-01-31`
~~~~~~~~~~~~~~~~~~~~

This release fixes a vulnerability where creating an authority automatically granted the selected owner role to the
authority creator, which allowed users to grant themselves to arbitrary roles. The owner role is no longer auto-assigned
when creating an authority.

Additionally, all authorities now receive a unique role upon creation. Previously, authorities using the same issuer
plugin would always share a role (for example, Entrust authorities always used the role "entrust"). Now, authorities
are associated with a unique role named in the format `issuerPlugin_authority_name_admin`. The creator will not be
automatically added to this role.

Other notable changes:
- The Endpoints UI page now displays endpoint source and allows filtering by source


1.1.0 - `2022-01-10`
~~~~~~~~~~~~~~~~~~~~

Introducing new Plugins AuthorizationPlugin(Plugin) and DomainAuthorizationPlugin(AuthorizationPlugin).
One can implement a DomainAuthorizationPlugin to check if caller is authorized to issue a certificate
for a given Common Name and Subject Alternative Name (SAN) of type DNSName (PR `#3889 <https://github.com/Netflix/lemur/pull/3889>`_)

Related to the above change (PR `#3889 <https://github.com/Netflix/lemur/pull/3889>`_), a new column `application_name`
is added to the `api_keys` table. Null values are allowed making sure this change is backward compatible.

Other notable changes:
- A task name is fixed from `identity_expiring_deployed_certificates` -> `identify_expiring_deployed_certificates`. The
old task name with typo is marked as deprecated and will be removed in future release flagging it as a breaking change.
(Thanks to `Bob Shannon <https://github.com/bobmshannon>`_)
- ID filter on certificates UI requires a numeric value.


1.0.0 - `2022-01-06`
~~~~~~~~~~~~~~~~~~~~

This is our first major release due to a dependency on Python 3.8.
Lemur is now using flake8>=4.0 and pyflakes>=2.4, requiring Python 3.8 or higher.
Our GitHub Actions Builds are currently on Python 3.8 and Python 3.9.


0.11.0 - `2022-01-05`
~~~~~~~~~~~~~~~~~~~~~

This release includes multiple improvements on many fronts.
The next release will be a major release, requiring Python 3.8 or higher.

Some of the notable changes in this release are:

- CloudFront Plugin: a new endpoint with rotation support
- Improved Endpoint expiration flow; the Sync job now expires old endpoints
- AWS ELB tag supports to opt-out of auto-rotate for load balancers
- Membership plugin
- Moving Travis Build to Node 16
- OAuth2 & Ping Config improvement
- Improved Certificate status check
- Improved ACME plugin:
    - reuse existing domain validation resulting in faster issuance
    - IP certificate issuance support, accompanied by UI support
    - emit remaining domain validation
- Azure destination: Switch to PCKS12 upload
- Improved logs, such as:
    - Warning logs for admin role assignment and authority creation
    - Audit logs in JSON format for better search
    - Improved SES logging

Special thanks to all who contributed to this release, notably:
- `Bob Shannon <https://github.com/bobmshannon>`_
- `sirferl <https://github.com/sirferl>`_
- `Sam Havron <https://github.com/havron>`_
- `Guillaume Dumont <https://github.com/dumontg>`_
- `Joe McRobot <https://github.com/JoeMcRobot>`_


0.10.0 - `2021-06-28`
~~~~~~~~~~~~~~~~~~~~~

This release introduces a breaking change (PR `#3646 <https://github.com/Netflix/lemur/pull/3646>`_) to the following API endpoint: 

- `POST /certificates/1/update/notify <https://lemur.readthedocs.io/en/latest/developer/index.html#lemur.certificates.views.Certificates.post>`_

The endpoint is now:

- `POST /certificates/1/update/switches <https://lemur.readthedocs.io/en/latest/developer/index.html#lemur.certificates.views.Certificates.post>`_

The new endpoint honors the existing `notify` request parameter, and additionally accepts a new `rotation` parameter. 
As a result of this change, the certificate table view now includes rotation switches and filtering by rotation status.


Other notable changes in this release:

- ACME:
    - New celery task to prevent duplicate certificates from being autorotated
    - ACME DNS-01 Challenges are supported in synchronous mode
    - DNS provider check fails gracefully if not found
- Authentication:
    - SSO auth now returns a newly created user during initial login
    - CSRF protection is added to OAuth2.0
- Notifications:
    - New reissue failed notification
    - New reissue with no endpoints notification
    - New revocation notification
- Plugins:
    - Plugin option values are validated server-side
    - Some plugin option validations updated to compile successfully server-side
- Database:
  - Source and Destination deletions remove certificate associations with new confirmation dialog
- Dependency updates and conflict resolutions
- Expanded audit logs

And several smaller bugfixes and improvements.

Special thanks to all who contributed to this release, notably:

- `havron <https://github.com/havron>`_
- `tho <https://github.com/tho>`_
- `mizzy <https://github.com/mizzy>`_


0.9.0 - `2021-03-17`
~~~~~~~~~~~~~~~~~~~~

This release fixes three critical vulnerabilities where an authenticated user could retrieve/access
unauthorized information. (Issue `#3463 <https://github.com/Netflix/lemur/issues/3463>`_)


0.8.1 - `2021-03-12`
~~~~~~~~~~~~~~~~~~~~

This release includes improvements on many fronts, such as:

- Notifications:
    - Enhanced SNS flow
    - Expiration Summary
    - CA expiration email
- EC algorithm as the default
- Improved revocation flow
- Localized AWS STS option
- Improved Lemur doc building
- ACME:
    - reduced failed attempts to 3x trials
    - support for selecting the chain (Let's Encrypt X1 transition)
    - revocation
    - http01 documentation
- Entrust:
    - Support for cross-signed intermediate CA
- Revised disclosure process
- Dependency updates and conflict resolutions

Special thanks to all who contributed to this release, notably:

- `peschmae  <https://github.com/peschmae>`_
- `atugushev  <https://github.com/atugushev>`_
- `sirferl   <https://github.com/sirferl>`_



0.8.0 - `2020-11-13`
~~~~~~~~~~~~~~~~~~~~

This release comes after more than two years and contains many interesting new features and improvements.
In addition to multiple new plugins, such as ACME-http01, ADCS, PowerDNS, UltraDNS, Entrust, SNS, many of Lemur's existing
flows have improved.

In the future, we plan to do frequent releases.


Summary of notable changes:

- AWS S3 plugin: added delete, get methods, and support for uploading/deleting acme tokens
- ACME plugin:
    - revamp of the plugin
    - support for http01 domain validation, via S3 and SFTP as destination for the acme token
    - support for CNAME delegated domain validation
    - store-acme-account-details
- PowerDNS plugin
- UltraDNS plugin
- ADCS plugin
- SNS plugin
- Entrust plugin
- Rotation:
    - respecting keyType and extensions
    - region-by-region rotation option
    - default to auto-rotate when cert attached to endpoint
    - default to 1y validity during rotation for multi-year browser-trusted certs
- Certificate: search_by_name, and important performance improvements
- UI
    - reducing the EC curve options to the relevant ones
    - edit option for notifications, destinations and sources
    - showing 13 month validity as default
    - option to hide certs expired since 3month
    - faster Permalink (no search involved)
    - commonName Auto Added as DNS in the UI
    - improved search and cert lookup
- celery tasks instead of crone, for better logging and monitoring
- countless bugfixes
    - group-lookup-fix-referral
    - url_context_path
    - duplicate notification
    - digicert-time-bug-fix
    - improved-csr-support
    - fix-cryptography-intermediate-ca
    - enhanced logging
    - vault-k8s-auth
    - cfssl-key-fix
    - cert-sync-endpoint-find-by-hash
    - nlb-naming-bug
    - fix_vault_api_v2_append
    - aid_openid_roles_provider_integration
    - rewrite-java-keystore-use-pyjks
    - vault_kv2


To see the full list of changes, you can run

    $ git log --merges --first-parent master         --pretty=format:"%h %<(10,trunc)%aN %C(white)%<(15)%ar%Creset %C(red bold)%<(15)%D%Creset %s" | grep -v "depend"


Special thanks to all who contributed to this release, notably:

- `peschmae  <https://github.com/peschmae>`_
- `sirferl   <https://github.com/sirferl>`_
- `lukasmrtvy  <https://github.com/lukasmrtvy>`_
- `intgr  <https://github.com/intgr>`_
- `kush-bavishi  <https://github.com/kush-bavishi>`_
- `alwaysjolley  <https://github.com/alwaysjolley>`_
- `jplana <https://github.com/jplana>`_
- `explody <https://github.com/explody>`_
- `titouanc <https://github.com/titouanc>`_
- `jramosf <https://github.com/jramosf>`_


Upgrading
---------

.. note:: This release will need a migration change. Please follow the `documentation <https://lemur.readthedocs.io/en/latest/administration.html#upgrading-lemur>`_ to upgrade Lemur.



0.7 - `2018-05-07`
~~~~~~~~~~~~~~~~~~

This release adds LetsEncrypt support with DNS providers Dyn, Route53, and Cloudflare, and expands on the pending certificate functionality.
The linux_dst plugin will also be deprecated and removed.

The pending_dns_authorizations and dns_providers tables were created. New columns
were added to the certificates and pending_certificates tables, (For the DNS provider ID), and authorities (For options).
Please run a database migration when upgrading.

The Let's Encrypt flow will run asynchronously. When a certificate is requested through the acme-issuer, a pending certificate
will be created. A cron needs to be defined to run `lemur pending_certs fetch_all_acme`. This command will iterate through all of the pending
certificates, request a DNS challenge token from Let's Encrypt, and set the appropriate _acme-challenge TXT entry. It will
then iterate through and resolve the challenges before requesting a certificate for each pending certificate. If a certificate
is successfully obtained, the pending_certificate will be moved to the certificates table with the appropriate properties.

Special thanks to all who helped with this release, notably:

- The folks at Cloudflare
- dmitryzykov
- jchuong
- seils
- titouanc


Upgrading
---------

.. note:: This release will need a migration change. Please follow the `documentation <https://lemur.readthedocs.io/en/latest/administration.html#upgrading-lemur>`_ to upgrade Lemur.

0.6 - `2018-01-02`
~~~~~~~~~~~~~~~~~~

Happy Holidays! This is a big release with lots of bug fixes and features. Below are the highlights and are not exhaustive.


Features:

* Per-certificate rotation policies, requires a database migration. The default rotation policy for all certificates is 30 days. Every certificate will gain a policy regardless of if auto-rotation is used.
* Adds per-user API Keys, allows users to issue multiple long-lived API tokens with the same permission as the user creating them.
* Adds the ability to revoke certificates from the Lemur UI/API, this is currently only supported for the digicert CIS and cfssl plugins.
* Allow destinations to support an export function. Useful for file system destinations e.g. S3 to specify the export plugin you wish to run before being sent to the destination.
* Adds support for uploading certificates to Cloudfront.
* Re-worked certificate metadata pane for improved readability.
* Adds support for LDAP user authentication

Bugs:

* Closed `#767 <https://github.com/Netflix/lemur/issues/767>`_ - Fixed issue with login redirect loop.
* Closed `#792 <https://github.com/Netflix/lemur/issues/792>`_ - Fixed an issue with a unique constraint was violated when replacing certificates.
* Closed `#752 <https://github.com/Netflix/lemur/issues/752>`_ - Fixed an internal server error when validating notification units.
* Closed `#684 <https://github.com/Netflix/lemur/issues/684>`_ - Fixed migration failure when null values encountered.
* Closes `#661 <https://github.com/Netflix/lemur/issues/661>`_ - Fixed an issue where default values were missing during clone operations.


Special thanks to all who helped with this release, notably:

- intgr
- SecurityInsanity
- johanneslange
- RickB17
- pr8kerl
- bunjiboys

See the full list of issues closed in `0.6 <https://github.com/Netflix/lemur/milestone/5>`_.

Upgrading
---------

.. note:: This release will need a migration change. Please follow the `documentation <https://lemur.readthedocs.io/en/latest/administration.html#upgrading-lemur>`_ to upgrade Lemur.



0.5 - `2016-04-08`
~~~~~~~~~~~~~~~~~~

This release is most notable for dropping support for python2.7. All Lemur versions >0.4 will now support python3.5 only.

Big thanks to neilschelly for quite a lot of improvements to the `lemur-cryptography` plugin.

Other Highlights:

* Closed `#501 <https://github.com/Netflix/lemur/issues/501>`_ - Endpoint resource as now kept in sync via an expiration mechanism. Such that non-existant endpoints gracefully fall out of Lemur. Certificates are never removed from Lemur.
* Closed `#551 <https://github.com/Netflix/lemur/pull/551>`_ - Added the ability to create a 4096 bit key during certificate creation. Closed `#528 <https://github.com/Netflix/lemur/pull/528>`_ to ensure that issuer plugins supported the new 4096 bit keys.
* Closed `#566 <https://github.com/Netflix/lemur/issues/566>`_ - Fixed an issue changing the notification status for  certificates without private keys.
* Closed `#594 <https://github.com/Netflix/lemur/issues/594>`_ - Added `replaced` field indicating if a certificate has been superseded.
* Closed `#602 <https://github.com/Netflix/lemur/issues/602>`_ - AWS plugin added support for ALBs for endpoint tracking.


Special thanks to all who helped with this release, notably:

- RcRonco
- harmw
- jeremyguarini

See the full list of issues closed in `0.5 <https://github.com/Netflix/lemur/milestone/4>`_.

Upgrading
---------

.. note:: This release will need a slight migration change. Please follow the `documentation <https://lemur.readthedocs.io/en/latest/administration.html#upgrading-lemur>`_ to upgrade Lemur.


0.4 - `2016-11-17`
~~~~~~~~~~~~~~~~~~

There have been quite a few issues closed in this release. Some notables:

* Closed `#284 <https://github.com/Netflix/lemur/issues/284>`_ - Created new models for `Endpoints` created associated AWS ELB endpoint tracking code. This was the major stated goal of this milestone and should serve as the basis for future enhancements of Lemur's certificate 'deployment' capabilities.
* Closed `#334 <https://github.com/Netflix/lemur/issues/334>`_ - Lemur not has the ability to restrict certificate expiration dates to weekdays.

Several fixes/tweaks to Lemurs python3 support (thanks chadhendrie!)

This will most likely be the last release to support python2.7 moving Lemur to target python3 exclusively. Please comment
on issue #340 if this negatively affects your usage of Lemur.

See the full list of issues closed in `0.4 <https://github.com/Netflix/lemur/milestone/3>`_.

Upgrading
---------

.. note:: This release will need a slight migration change. Please follow the `documentation <https://lemur.readthedocs.io/en/latest/administration.html#upgrading-lemur>`_ to upgrade Lemur.


0.3.0 - `2016-06-06`
~~~~~~~~~~~~~~~~~~~~

This is quite a large upgrade, it is highly advised you backup your database before attempting to upgrade as this release
requires the migration of database structure as well as data.


Upgrading
---------

Please follow the `documentation <https://lemur.readthedocs.io/en/latest/administration.html#upgrading-lemur>`_ to upgrade Lemur.


Source Plugin Owners
--------------------

The dictionary returned from a source plugin has changed keys from `public_certificate` to `body` and `intermediate_certificate` to chain.


Issuer Plugin Owners
--------------------

This release may break your plugins, the keys in `issuer_options` have been changed from `camelCase` to `under_score`.
This change was made to break an undue reliance on downstream options maintains a more pythonic naming convention. Renaming
these keys should be fairly trivial, additionally pull requests have been submitted to affected plugins to help ease the transition.

.. note:: This change only affects issuer plugins and does not affect any other types of plugins.


* Closed `#63 <https://github.com/Netflix/lemur/issues/63>`_ - Validates all endpoints with Marshmallow schemas, this allows for
    stricter input validation and better error messages when validation fails.
* Closed `#146 <https://github.com/Netflix/lemur/issues/146>`_ - Moved authority type to first pane of authority creation wizard.
* Closed `#147 <https://github.com/Netflix/lemur/issues/147>`_ - Added and refactored the relationship between authorities and their
    root certificates. Displays the certificates (and chains) next to the authority in question.
* Closed `#199 <https://github.com/Netflix/lemur/issues/199>`_ - Ensures that the dates submitted to Lemur during authority and
    certificate creation are actually dates.
* Closed `#230 <https://github.com/Netflix/lemur/issues/230>`_ - Migrated authority dropdown to an ui-select based dropdown, this
    should be easier to determine what authorities are available and when an authority has actually been selected.
* Closed `#254 <https://github.com/Netflix/lemur/issues/254>`_ - Forces certificate names to be generally unique. If a certificate name
    (generated or otherwise) is found to be a duplicate we increment by appending a counter.
* Closed `#275 <https://github.com/Netflix/lemur/issues/275>`_ - Switched to using Fernet generated passphrases for exported items.
    These are more sounds that pseudo random passphrases generated before and have the nice property of being in base64.
* Closed `#278 <https://github.com/Netflix/lemur/issues/278>`_ - Added ability to specify a custom name to certificate creation, previously
    this was only available in the certificate import wizard.
* Closed `#281 <https://github.com/Netflix/lemur/issues/281>`_ - Fixed an issue where notifications could not be removed from a certificate
    via the UI.
* Closed `#289 <https://github.com/Netflix/lemur/issues/289>`_ - Fixed and issue where intermediates were not being properly exported.
* Closed `#315 <https://github.com/Netflix/lemur/issues/315>`_ - Made how roles are associated with certificates and authorities much more
    explicit, including adding the ability to add roles directly to certificates and authorities on creation.



0.2.2 - 2016-02-05
~~~~~~~~~~~~~~~~~~

* Closed `#234 <https://github.com/Netflix/lemur/issues/234>`_ - Allows export plugins to define whether they need
    private key material (default is True)
* Closed `#231 <https://github.com/Netflix/lemur/issues/231>`_ - Authorities were not respecting 'owning' roles and their
    users
* Closed `#228 <https://github.com/Netflix/lemur/issues/228>`_ - Fixed documentation with correct filter values
* Closed `#226 <https://github.com/Netflix/lemur/issues/226>`_ - Fixes issue were `import_certificate` was requiring
    replacement certificates to be specified
* Closed `#224 <https://github.com/Netflix/lemur/issues/224>`_ - Fixed an issue where NPM might not be globally available (thanks AlexClineBB!)
* Closed `#221 <https://github.com/Netflix/lemur/issues/234>`_ - Fixes several reported issues where older migration scripts were
    missing tables, this change removes pre 0.2 migration scripts
* Closed `#218 <https://github.com/Netflix/lemur/issues/234>`_ - Fixed an issue where export passphrases would not validate


0.2.1 - 2015-12-14
~~~~~~~~~~~~~~~~~~

* Fixed bug with search not refreshing values
* Cleaned up documentation, including working supervisor example (thanks rpicard!)
* Closed #165 - Fixed an issue with email templates
* Closed #188 - Added ability to submit third party CSR
* Closed #176 - Java-export should allow user to specify truststore/keystore
* Closed #176 - Extended support for exporting certificate in P12 format


0.2.0 - 2015-12-02
~~~~~~~~~~~~~~~~~~

* Closed #120 - Error messages not displaying long enough
* Closed #121 - Certificate create form should not be valid until a Certificate Authority object is available
* Closed #122 - Certificate API should allow for the specification of preceding certificates
    You can now target a certificate(s) for replacement. When specified the replaced certificate will be marked as
    'inactive'. This means that there will be no notifications for that certificate.
* Closed #139 - SubCA autogenerated descriptions for their certs are incorrect
* Closed #140 - Permalink does not change with filtering
* Closed #144 - Should be able to search certificates by domains covered, included wildcards
* Closed #165 - Cleaned up expiration notification template
* Closed #160 - Cleaned up quickstart documentation (thanks forkd!)
* Closed #144 - Now able to search by all domains in a given certificate, not just by common name


0.1.5 - 2015-10-26
~~~~~~~~~~~~~~~~~~

* **SECURITY ISSUE**: Switched from use an AES static key to Fernet encryption.
  Affects all versions prior to 0.1.5. If upgrading this will require a data migration.
  see: `Upgrading Lemur <https://lemur.readthedocs.io/administration#UpgradingLemur>`_
