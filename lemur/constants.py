"""
.. module: lemur.constants
    :copyright: (c) 2015 by Netflix Inc.
    :license: Apache, see LICENSE for more details.
"""
SAN_NAMING_TEMPLATE = "SAN-{subject}-{issuer}-{not_before}-{not_after}"
DEFAULT_NAMING_TEMPLATE = "{subject}-{issuer}-{not_before}-{not_after}"
NONSTANDARD_NAMING_TEMPLATE = "{issuer}-{not_before}-{not_after}"

SUCCESS_METRIC_STATUS = 'success'
FAILURE_METRIC_STATUS = 'failure'
