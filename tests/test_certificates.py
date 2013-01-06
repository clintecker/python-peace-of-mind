from unittest import TestCase
from peace_of_mind import certificates
from peace_of_mind.certificates import (ERROR_SSL_CERT_EXPIRED,
										ERROR_SSL_CERT_NOT_YET_VALID,
										ERROR_SSL_CERT_HOST_MISMATCH,
										ERROR_SSL_CERT_UNTRUSTED_AUTHORITY,
										ERROR_SSL_CERT_COULD_NOT_BE_OBTAINED,
										UTCTIME_FORMAT)
from ssl import SSLError
import os
import datetime

class TestCertificates(TestCase):
	def setUp(self):
		self._test_domain = 'www.example.com'
		self._ca_cert_path = os.path.join(os.path.dirname(__file__), 'certs', 'ca_certs.pem')
		self.checker = certificates.CertificateChecker(
			domain=self._test_domain,
			ca_certs=self._ca_cert_path
			)
		self._original_get_certificate = self.checker._get_certificate


	def tearDown(self):
		self.checker._get_certificate = self._original_get_certificate


	def _get_default_not_before(self):
		today = datetime.datetime.utcnow()
		not_before = today - datetime.timedelta(days=5)
		return not_before


	def _get_default_not_after(self):
		today = datetime.datetime.utcnow()
		not_after = today + datetime.timedelta(days=5)
		return not_after


	def _get_mock_certificate(self, **options):
		certificate = dict()
		not_before = options.get('not_before', self._get_default_not_before())
		not_after = options.get('not_after', self._get_default_not_after())
		alt_hosts = options.get('alt_hosts')
		common_name = options.get('common_name', self._test_domain)

		if not_before and isinstance(not_before, datetime.datetime):
			certificate['notBefore'] = not_before.strftime(UTCTIME_FORMAT)
		if not_after and isinstance(not_after, datetime.datetime):
			certificate['notAfter'] = not_after.strftime(UTCTIME_FORMAT)
		if alt_hosts:
			certificate['subjectAltName'] = [('DNS', host) for host in alt_hosts]
		if common_name:
			certificate['subject'] = ((('commonName', common_name),),)
		return certificate


	def _setup_unavailable_certificate(self):
		def mock_get_certificate(*args, **kwargs):
			error = SSLError(8, "Certificate is unavailble")
			raise error
		self.checker._get_certificate = mock_get_certificate


	def _setup_self_signed_certificate(self):
		def mock_get_certificate(*args, **kwargs):
			check_ca = kwargs.get('check_ca', True)
			if check_ca:
				error = SSLError(1, "Self-signed")
				raise error
			else:
				return self._get_mock_certificate()
		self.checker._get_certificate = mock_get_certificate


	def _setup_mock_certificate(self, mock_certificate):
		def mock_get_certificate(*args, **kwargs):
			return mock_certificate
		self.checker._get_certificate = mock_get_certificate


	def test_certificate_checker_basic(self):
		self._setup_mock_certificate(self._get_mock_certificate())
		err = None
		try:
			self.checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is None


	def test_certificate_checker_unavailable(self):
		self._setup_unavailable_certificate()
		err = None
		try:
			self.checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is not None
			assert type(err) == certificates.SSLCertificateError
			assert err.errors
			assert ERROR_SSL_CERT_COULD_NOT_BE_OBTAINED & err.errors


	def test_certificate_checker_self_signed(self):
		self._setup_self_signed_certificate()
		err = None
		try:
			self.checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is not None
			assert type(err) == certificates.SSLCertificateError
			assert err.errors
			assert ERROR_SSL_CERT_UNTRUSTED_AUTHORITY & err.errors


	def test_certificate_checker_common_name_mistmatch(self):
		self._setup_mock_certificate(self._get_mock_certificate(
			common_name='different.example.com'
			))
		err = None
		try:
			self.checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is not None
			assert type(err) == certificates.SSLCertificateError
			assert err.errors
			assert ERROR_SSL_CERT_HOST_MISMATCH & err.errors


	def test_certificate_checker_alt_name_mismatch(self):
		certificate = self._get_mock_certificate(
			alt_hosts=['different.example.com']
			)
		del certificate['subject']
		self._setup_mock_certificate(certificate)
		err = None
		try:
			self.checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is not None
			assert type(err) == certificates.SSLCertificateError
			assert err.errors
			assert ERROR_SSL_CERT_HOST_MISMATCH & err.errors


	def test_certificate_checker_alt_name_match(self):
		self._setup_mock_certificate(self._get_mock_certificate(
			alt_hosts=[
				self._test_domain,
				'login.example.com'
				],
			common_name='mail.example.com'
			))
		err = None
		try:
			self.checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is None


	def test_certificate_checker_alt_name_wildcard_match(self):
		self._setup_mock_certificate(self._get_mock_certificate(
			alt_hosts=['*.example.com'],
			common_name='mail.example.com'
			))
		err = None
		try:
			self.checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is None


	def test_certificate_expired(self):
		past_time = datetime.datetime.now() - datetime.timedelta(days=5)
		certificate = self._get_mock_certificate(not_after=past_time)
		self._setup_mock_certificate(certificate)
		err = None
		try:
			self.checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is not None
			assert type(err) == certificates.SSLCertificateError
			assert err.errors
			assert ERROR_SSL_CERT_EXPIRED & err.errors


	def test_certificate_not_yet_valid(self):
		future_time = datetime.datetime.now() + datetime.timedelta(days=5)
		certificate = self._get_mock_certificate(not_before=future_time)
		self._setup_mock_certificate(certificate)
		err = None

		try:
			self.checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is not None
			assert type(err) == certificates.SSLCertificateError
			assert err.errors
			assert ERROR_SSL_CERT_NOT_YET_VALID & err.errors


	def test_certificate_combo_errors(self):
		future_time = datetime.datetime.now() + datetime.timedelta(days=5)
		past_time = datetime.datetime.now() - datetime.timedelta(days=5)
		certificate = self._get_mock_certificate(
			not_before  = future_time,
			not_after   = past_time,
			alt_hosts   = ['*.google.com', 'mail.yahoo.com'],
			common_name = 'bing.com'
			)
		self._setup_mock_certificate(certificate)
		err = None
		try:
			self.checker.check()
		except Exception, e:
			err = e
		finally:
			assert err is not None
			assert type(err) == certificates.SSLCertificateError
			assert err.errors
			assert ERROR_SSL_CERT_NOT_YET_VALID & err.errors
			assert ERROR_SSL_CERT_EXPIRED & err.errors
			assert ERROR_SSL_CERT_HOST_MISMATCH & err.errors

