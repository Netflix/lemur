import unittest
from unittest.mock import patch
from lemur.plugins.lemur_fastly import plugin


Class TestFastlyPlugin(unittest.TestCase):
    priv_data = {
        "data": {
            "id": "testid",
            "attributes": {
                "name": "testname",
                "public_key_sha1": "sha1234567890",
            }
        }
    }

    priv_res = {
        "id": "testid",
        "name": "testname",
        "sha1": "sha123456789",
    }

    @patch('lemur.plugins.lemur_fastly.plugin._get')
    def test_get_priv(self, mocked):
        mocked.return_value = priv_data
        self.assertEqual(priv_res, get_private_keys())


#    def true_false(self):
#        self.assertTrue(plugin.true_or_false(True)
#        self.assertFalse(plugin.true_or_false(False)
