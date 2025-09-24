import unittest

from flask import Flask


class TestAdcs(unittest.TestCase):
    def setUp(self):
        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = Flask("lemur_test_adcs")
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_create_authority(self):
        from lemur.plugins.lemur_adcs.plugin import ADCSIssuerPlugin

        options = {"name": "test ADCS authority"}
        adcs_root, intermediate, role = ADCSIssuerPlugin.create_authority(options)
        assert role == [
            {"username": "", "password": "", "name": "adcs_test_ADCS_authority_admin"}
        ]
