"""
.. module: lemur.common.health
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint

mod = Blueprint('healthCheck', __name__)


@mod.route('/healthcheck')
def health():
    return 'ok'
