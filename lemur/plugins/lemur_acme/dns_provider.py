"""
.. module: lemur.plugins.lemur_acme.dns_provider
    :platform: Unix
    :synopsis: Small helper to figure out wich DNS provider to use.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Harm Weites <harm@weites.com>
"""

from flask import current_app


dnsp = current_app.config.get('ACME_DNS_PROVIDER', 'route53')
current_app.logger.debug("Using DNS provider: {0}".format(dnsp))

if dnsp == 'route53':
    from .route53 import * # NOQA
if dnsp == 'cloudflare':
    from .cloudflare import * # NOQA
