"""
Perform queries around SSL Certificates attached to Internet domain names
"""
import socket
import tempfile
import ssl
from dateutil import parser
import datetime
from backports.ssl_match_hostname import match_hostname, CertificateError


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

UTCTIME_FORMAT = "%Y%m%d%H%M%SZ"

class SSLCertificateError(Exception):
	"""
	Raised when an SSL Certificate fails validation
	"""
	def __init__(self, *args, **kwargs):
		"""
		A bitfield indicating which errors were encountered.

		`self.errors` will be set if an `errors` parameter is given when initialized.
		"""
		self.errors = kwargs.get('errors')


class CertificateChecker(object):
	"""
	Given an HTTPS web address, this code would obtain the SSL Certificate
	and verify certain parameters about it.

	Possibilities are expiration date, security levels, domain matching,
	revocation lists.
	"""
	def __init__(self, domain, ca_certs, port=443):
		"""
		Arguments:

		* `domain`: A domain with a TLS server listening on a port.
		* `ca_certs`: The full path to a file containing a list of concatenated PEM files for the Certificate Authorities you trust.
		* `port`: The TCP port the server is listening on.
		"""
		self._domain       = domain
		self._port         = port
		self._ca_certs     = ca_certs
		self._certificate = None


	@classmethod
	def _get_address(cls, domain, port=443):
		"""
		Returns an address tuple that can be passed to :py:meth:`~peace_of_mind.certificates.CertificateChecker.get_sslsocket`

		Arguments:

		* `domain`: A fully qualified domain name.
		* `port`: The TCP port to connect to.
		"""
		hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(domain)
		return (ipaddrlist[0], port)


	def _get_sslsocket(self, check_ca=True):
		"""
		Initializes and returns an un-conncted SSL socket.

		Arguments:

		* `check_ca`: Indicates whether or not the SSL socket should be configured to validate against a Certificate Authority.
		"""
		sock = socket.socket()
		if check_ca and self._ca_certs:
			cert_reqs = ssl.CERT_REQUIRED
			ca_certs = self._ca_certs
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


	def _get_certificate(self, check_ca=True):
		"""
		Retrieve the SSL certificate for the configured domain and port

		Arguments:

		* `check_ca`: Indicates whether or not the certificate should be validated against the Certificate Authorities

		Returns a certificate object that can be used in validator methods.
		"""
		binary_certificate = None
		decoded_certificate = None
		address = CertificateChecker._get_address(self._domain, self._port)
		ssl_socket = self._get_sslsocket(check_ca=check_ca)
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


	def _certificate_is_expired(self, certificate):
		"""
		Determines whether or not an SSL certificate has expired.

		Arguments:

		* `certificate`: A certificate object as returned by :py:meth:`~peace_of_mind.certificates.CertificateChecker.get_certificate`

		Returns False or :py:const:`~peace_of_mind.certificates.ERROR_SSL_CERT_EXPIRED` if the certificate has expired.
		"""
		if 'notAfter' in certificate:
			not_after = parser.parse(certificate['notAfter']).replace(tzinfo=None)
			now = datetime.datetime.utcnow()
			if now > not_after:
				return ERROR_SSL_CERT_EXPIRED
		return False


	def _certificate_is_not_yet_valid(self, certificate):
		"""
		Determines whether or not an SSL certificate is not yet valid.

		Arguments:

		* `certificate`: A certificate object as returned by :py:meth:`~peace_of_mind.certificates.CertificateChecker.get_certificate`

		Returns False or :py:const:`~peace_of_mind.certificates.ERROR_SSL_CERT_NOT_YET_VALID` if the certificate has expired.
		"""
		if 'notBefore' in certificate:
			not_before = parser.parse(certificate['notBefore']).replace(tzinfo=None)
			if datetime.datetime.utcnow() < not_before:
				return ERROR_SSL_CERT_NOT_YET_VALID
		return False


	def _certificate_hostname_mismatch(self, certificate):
		"""
		Determines whether or not a given certificate matches the previously configured domain.

		The `altSubjectName` property is checked first, taking into account the explicit and wildcard fields there.

		If the `altSubjectName` property is not present, the `commonName` property of the `subject` field is checked.

		Arguments:

		* `certificate`: A certificate object as returned by :py:meth:`~peace_of_mind.certificates.CertificateChecker.get_certificate`

		Returns False or :py:const:`~peace_of_mind.certificates.ERROR_SSL_CERT_HOST_MISMATCH` if the certificate has expired.
		"""
		try:
			match_hostname(certificate, self._domain)
		except CertificateError:
			return ERROR_SSL_CERT_HOST_MISMATCH
		return False

	@property
	def _verbose_checks(self):
		"""
		Returns a list of the validations to run on cerificates
		"""
		return [
			self._certificate_is_expired,
			self._certificate_is_not_yet_valid,
			self._certificate_hostname_mismatch
		]


	def _full_error_string(self, errors):
		"""
		Converts an array of bitfield codes and produces human-readable error strings

		Arguments:

		* `errors`: An array of bitfields

		Returns a list of human-readable error strings.
		"""
		error_strings = []
		for errno, errstr in ERROR_STRINGS.iteritems():
			if errors & errno:
				error_strings.append(errstr)
		return ", ".join(error_strings)


	def check(self):
		"""
		Obtains a domain's SSL certificate and executes a series of validations.

		Either returns True or raises :py:exc:`~peace_of_mind.certificates.SSLCertificateError`. The raised exception instance has an `errors` property which contains a bitfield indicating which errors were encountered.  The `message` of the exception has a human-friendly version of what happened.

		Currently the following things will be checked:

		* Whether or not the SSL Certificate could be obtained
		* Whether the certificate has already expired
		* Whether the certificate is not yet valid
		* Whether or not the certificate is valid for the given domain
		* Whether or not the certificate's chain of trust can be verified

		"""
		certificate = None
		certificate_valid = True
		errors = 0

		try:
			certificate = self._get_certificate()
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
				certificate = self._get_certificate(check_ca=False)

		if certificate:
			for check_fn in self._verbose_checks:
				error_code = check_fn(certificate)
				if error_code:
					certificate_valid = False
					errors |= error_code

		if not certificate_valid:
			e = SSLCertificateError("The certificate is not valid: {}".format(self._full_error_string(errors)), errors=errors)
			raise e

		return certificate_valid
