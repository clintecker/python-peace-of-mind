"""
Perform queries around SSL Certificates attached to Internet domain names
"""
import socket
import tempfile
import ssl
from dateutil import parser
import datetime
from backports.ssl_match_hostname import match_hostname, CertificateError


class SSLCertificateError(Exception):
	"""
	Raised when an SSL Certificate fails validation
	"""
	def __init__(self, *args, **kwargs):
		self.errors = kwargs.get('errors')


ERROR_SSL_CERT_EXPIRED = 1
ERROR_SSL_CERT_NOT_YET_VALID = 2
ERROR_SSL_CERT_HOST_MISMATCH = 4
ERROR_SSL_CERT_UNTRUSTED_AUTHORITY = 8
ERROR_SSL_CERT_COULD_NOT_BE_OBTAINED = 16

ERROR_STRINGS = {
	ERROR_SSL_CERT_EXPIRED:       "certificate is expired",
	ERROR_SSL_CERT_NOT_YET_VALID: "certificate is not yet valid",
	ERROR_SSL_CERT_HOST_MISMATCH: "certificate hostname mismatch",
	ERROR_SSL_CERT_UNTRUSTED_AUTHORITY: "certificate is not signed by a trusted authority",
	ERROR_SSL_CERT_COULD_NOT_BE_OBTAINED: "certificate could not be obtained"
}

class CertificateChecker(object):
	"""
	Given an HTTPS web address, this code would obtain the SSL Certificate
	and verify certain parameters about it.

	Possibilities are expiration date, security levels, domain matching,
	revocation lists.
	"""
	def __init__(self, domain, ca_certs, port=443):
		"""
		`domain`:   a domain with a TLS server listening on a port
		`ca_certs`:	the full path to a file containing a list of concatenated
					PEM files for the Certificate Authorities you trust.
		`port`:     the port the server is listening on, defaults to 443
		"""
		self.domain       = domain
		self.port         = port
		self.ca_certs     = ca_certs
		self._certificate = None


	@classmethod
	def get_address(cls, domain, port=443):
		hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(domain)
		return (ipaddrlist[0], port)


	def get_sslsocket(self, check_ca=True):
		"""
		We need to return an unconnected socket
		"""
		sock = socket.socket()
		if check_ca and self.ca_certs:
			cert_reqs = ssl.CERT_REQUIRED
			ca_certs = self.ca_certs
		else:
			cert_reqs = ssl.CERT_NONE
			ca_certs = None

		sslsocket = ssl.wrap_socket(
			sock,
			ssl_version=ssl.PROTOCOL_SSLv3,
			cert_reqs=cert_reqs,
			ca_certs=ca_certs
			)

		return sslsocket


	def get_certificate(self, check_ca=True):
		binary_certificate = None
		decoded_certificate = None
		address = CertificateChecker.get_address(self.domain, self.port)
		ssl_socket = self.get_sslsocket(check_ca=check_ca)
		err = None

		try:
			ssl_socket.connect(address)
		except Exception, e:
			err = e
		else:
			if not check_ca:
				binary_certificate = ssl_socket.getpeercert(True)
			else:
				decoded_certificate = ssl_socket.getpeercert(False)

			if not decoded_certificate and binary_certificate:
				certificate_data = ssl.DER_cert_to_PEM_cert(binary_certificate)
				certificate_file = tempfile.NamedTemporaryFile(mode='w', delete=True)
				certificate_file.write(certificate_data)
				certificate_file.flush()
				decoded_certificate = ssl._ssl._test_decode_cert(certificate_file.name, True)
				certificate_file.close()
		finally:
			ssl_socket.close()

		if err:
			raise err

		return decoded_certificate


	def certificate_is_expired(self, certificate):
		if 'notAfter' in certificate:
			not_after = parser.parse(certificate['notAfter']).replace(tzinfo=None)
			now = datetime.datetime.utcnow()
			if now > not_after:
				return ERROR_SSL_CERT_EXPIRED
		return False


	def certificate_is_not_yet_valid(self, certificate):
		if 'notBefore' in certificate:
			not_before = parser.parse(certificate['notBefore']).replace(tzinfo=None)
			if datetime.datetime.utcnow() < not_before:
				return ERROR_SSL_CERT_NOT_YET_VALID
		return False

	def certificate_hostname_mismatch(self, certificate):
		try:
			match_hostname(certificate, self.domain)
		except CertificateError:
			return ERROR_SSL_CERT_HOST_MISMATCH
		return False

	@property
	def verbose_checks(self):
		return [
			self.certificate_is_expired,
			self.certificate_is_not_yet_valid,
			self.certificate_hostname_mismatch
		]


	def full_error_string(self, errors):
		error_strings = []
		for errno, errstr in ERROR_STRINGS.iteritems():
			if errors & errno:
				error_strings.append(errstr)
		return ", ".join(error_strings)


	def check(self):
		certificate = None
		certificate_valid = True
		errors = 0

		try:
			certificate = self.get_certificate()
		except ssl.SSLError, e:
			certificate_valid = False
			ssl_errno = e.errno

			if ssl_errno == 8:
				errors |= ERROR_SSL_CERT_COULD_NOT_BE_OBTAINED
			elif ssl_errno != 0:
				certificate_valid = False
				if ssl_errno == 1:
					errors |= ERROR_SSL_CERT_UNTRUSTED_AUTHORITY

				# Get the certificated and bypass any crypto validation
				certificate = self.get_certificate(check_ca=False)

		if certificate:
			for check_fn in self.verbose_checks:
				error_code = check_fn(certificate)
				if error_code:
					certificate_valid = False
					errors |= error_code

		if not certificate_valid:
			e = SSLCertificateError("The certificate is not valid: {}".format(self.full_error_string(errors)), errors=errors)
			raise e

		return certificate_valid
