import unittest
from nose.tools import eq_

from lemur import app

test_app = app.test_client()

HEADERS = {'Content-Type': 'application/json'}


def check_content_type(headers):
    eq_(headers['Content-Type'], 'application/json')


class LemurTestCase(unittest.TestCase):
    pass
