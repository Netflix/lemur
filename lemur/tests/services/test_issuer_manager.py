from lemur import app
from lemur.tests import LemurTestCase
from lemur.tests.constants import TEST_CERT, TEST_KEY

from lemur.certificates.models import Certificate

from moto import mock_iam, mock_sts


class ManagerTestCase(LemurTestCase):
    def test_validate_authority(self):
        pass

    def test_get_all_authorities(self):
        from lemur.common.services.issuers.manager import get_all_authorities
        authorities = get_all_authorities()
        self.assertEqual(len(authorities), 3)

    def test_get_all_issuers(self):
        from lemur.common.services.issuers.manager import get_all_issuers
        issuers = get_all_issuers()
        self.assertEqual(len(issuers) > 1)

