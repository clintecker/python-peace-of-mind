from unittest import TestCase
from peace_of_mind import certificates
from peace_of_mind.certificates import (ERROR_SSL_CERT_EXPIRED,
										ERROR_SSL_CERT_NOT_YET_VALID,
										ERROR_SSL_CERT_HOST_MISMATCH,
										ERROR_SSL_CERT_UNTRUSTED_AUTHORITY,
										ERROR_SSL_CERT_COULD_NOT_BE_OBTAINED)
import os

class TestCertificates(TestCase):
	def setUp(self):
		self.test_domain = 'www.google.com'
		self.self_signed_domain = 'alice.arsdev.net'
		self.ca_cert_path = os.path.join(os.path.dirname(__file__), 'certs', 'ca_certs.pem')
		self.checker = certificates.CertificateChecker(
			domain=self.test_domain,
			ca_certs=self.ca_cert_path
			)

	def test_certificate_checker_basic(self):
		checker = certificates.CertificateChecker(
			domain=self.test_domain,
			ca_certs=self.ca_cert_path
			)
		assert checker.check()

	def test_certificate_checker_self_signed(self):
		checker = certificates.CertificateChecker(
			domain=self.self_signed_domain,
			ca_certs=self.ca_cert_path
			)

		err = None

		try:
			checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is not None
			assert type(err) == certificates.SSLCertificateError
			assert err.errors
			assert ERROR_SSL_CERT_UNTRUSTED_AUTHORITY & err.errors

	def test_certificate_checker_host_mistmatch(self):
		checker = certificates.CertificateChecker(
			domain=self.self_signed_domain,
			ca_certs=self.ca_cert_path
			)

		err = None

		try:
			checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is not None
			assert type(err) == certificates.SSLCertificateError
			assert err.errors
			assert ERROR_SSL_CERT_HOST_MISMATCH & err.errors
