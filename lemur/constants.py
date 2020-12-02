"""
.. module: lemur.constants
    :copyright: (c) 2018 by Netflix Inc.
    :license: Apache, see LICENSE for more details.
"""
from enum import IntEnum

SAN_NAMING_TEMPLATE = "SAN-{subject}-{issuer}-{not_before}-{not_after}"
DEFAULT_NAMING_TEMPLATE = "{subject}-{issuer}-{not_before}-{not_after}"
NONSTANDARD_NAMING_TEMPLATE = "{issuer}-{not_before}-{not_after}"

SUCCESS_METRIC_STATUS = "success"
FAILURE_METRIC_STATUS = "failure"

CERTIFICATE_KEY_TYPES = [
    "RSA2048",
    "RSA4096",
    "ECCPRIME192V1",
    "ECCPRIME256V1",
    "ECCSECP192R1",
    "ECCSECP224R1",
    "ECCSECP256R1",
    "ECCSECP384R1",
    "ECCSECP521R1",
    "ECCSECP256K1",
    "ECCSECT163K1",
    "ECCSECT233K1",
    "ECCSECT283K1",
    "ECCSECT409K1",
    "ECCSECT571K1",
    "ECCSECT163R2",
    "ECCSECT233R1",
    "ECCSECT283R1",
    "ECCSECT409R1",
    "ECCSECT571R2",
]


# As per RFC 5280 section 5.3.1 (https://tools.ietf.org/html/rfc5280#section-5.3.1)
class CRLReason(IntEnum):
    unspecified = 0,
    keyCompromise = 1,
    cACompromise = 2,
    affiliationChanged = 3,
    superseded = 4,
    cessationOfOperation = 5,
    certificateHold = 6,
    removeFromCRL = 8,
    privilegeWithdrawn = 9,
    aACompromise = 10
