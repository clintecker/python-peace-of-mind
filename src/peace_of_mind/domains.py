"""
Domain Name validation and queries
"""
import datetime
import whois

class WHOISNotFoundError(Exception):
	"""
	Raised when a domain's WHOIS information could not be located
	"""

class DomainExpirationError(Exception):
	"""
	Raised when a domain is nearing expiration
	"""

class DomainChecker(object):
	"""
	Perform checks around domain names
	"""
	def __init__(self, domain_name):
		self._domain_name = domain_name
		self._domain = None

	@property
	def domain(self):
		if not self._domain:
			self._domain = whois.query(self._domain_name)
		if not self._domain:
			raise WHOISNotFoundError("Could not find WHOIS information for {}".format(self._domain_name))
		return self._domain

	@property
	def _expiration_date(self):
		"""
		Obtain the expiration data for this checker's domain name
		"""
		return self.domain.expiration_date.date()

	def check_expiration(self, threshhold=None):
		"""
		Throw a warning if the expiration date for this checker is within
		the given threshhold.
		"""
		_expiration_date = self._expiration_date
		now = datetime.date.today()
		if threshhold:
			warn_date = _expiration_date - datetime.timedelta(days=threshhold)
			if now >= warn_date:
				raise DomainExpirationError("Warning: The domain {} is expiring on {} which is within your threshhold of {} days.".format(self._domain_name, self._expiration_date, threshhold))
		days_remaining_delta = _expiration_date - now
		return days_remaining_delta.days

