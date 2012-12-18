from unittest import TestCase
from peace_of_mind import certificates

class TestCertificates(TestCase):
	def setUp(self):
		pass

	def test_certificate_checker_basic(self):
		checker = certificates.CertificateChecker()
		assert checker
