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

        >>> from peace_of_mind import domains
        >>> dc = domains.DomainChecker('barackobama.com')
        >>> dc.check_expiration(threshhold=50)
        1086
        >>> dc.check_expiration(threshhold=1100)
        Traceback (most recent call last):
          File "<console>", line 1, in <module>
          File "/Users/clintecker/projects/peace_of_mind/src/peace_of_mind/domains.py", line 72, in check_expiration
            warn_date = _expiration_date - datetime.timedelta(days=threshhold)
        DomainExpirationError: Warning: The domain barackobama.com is expiring on 2015-12-28 which is within your threshhold of 1100 days.
    """
    def __init__(self, domain_name):
        """
        Arguments:

        * ``domain_name``: The domain name to query (eg. 'example.com')
        """
        self._domain_name = domain_name
        self._domain = None

    @property
    def domain(self):
        """
        Provides a memoized ``domain`` object as returned by the ``whois`` library.

        If the domain is non-existent, or whois information cannot be found, :py:exc:`~peace_of_mind.domains.WHOISNotFoundError` will be raised.
        """
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

        Arguments:

        * ``threshhold``: Specified in days.  If the domain expires within this window, :py:exc:`~peace_of_mind.domains.DomainExpirationError` will be raised.

        If ``threshhold`` is not specified, no exceptions will be raised under any circumstance.  If no exception was raised, regardless of the value of ``threshhold``, the number of days until the domain expires will be returned.

        """
        _expiration_date = self._expiration_date
        now = datetime.date.today()
        if threshhold:
            warn_date = _expiration_date - datetime.timedelta(days=threshhold)
            if now >= warn_date:
                raise DomainExpirationError("Warning: The domain {} is expiring on {} which is within your threshhold of {} days.".format(self._domain_name, self._expiration_date, threshhold))
        days_remaining_delta = _expiration_date - now
        return days_remaining_delta.days

