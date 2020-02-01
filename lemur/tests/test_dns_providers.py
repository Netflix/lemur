import unittest
from lemur.dns_providers import util as dnsutil


class TestDNSProvider(unittest.TestCase):
    def test_is_valid_domain(self):
        self.assertTrue(dnsutil.is_valid_domain("example.com"))
        self.assertTrue(dnsutil.is_valid_domain("foo.bar.org"))
        self.assertTrue(dnsutil.is_valid_domain("_acme-chall.example.com"))
        self.assertFalse(dnsutil.is_valid_domain("e/xample.com"))
        self.assertFalse(dnsutil.is_valid_domain("exam\ple.com"))
        self.assertFalse(dnsutil.is_valid_domain("*.example.com"))
