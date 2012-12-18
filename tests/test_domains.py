from unittest import TestCase
from peace_of_mind import domains
from peace_of_mind.domains import (DomainExpirationError,
								   WHOISNotFoundError)

from mock import patch
import datetime

class TestDomains(TestCase):
	def setUp(self):
		today = datetime.datetime.now()
		self.test_domain = 'clintecker.com'
		self.checker = domains.DomainChecker(domain_name=self.test_domain)

		self.expiration_date_differential_days = 100
		self.mock_expiration_date = today + datetime.timedelta(days=self.expiration_date_differential_days)

		self._whois_client_patcher = patch('peace_of_mind.domains.whois')
		self.mock_whois_client = self._whois_client_patcher.start()

		self.mock_whois_client.query.return_value.expiration_date = self.mock_expiration_date

		self.addCleanup(self._whois_client_patcher.stop)

	def test_domain_checker_no_threshhold(self):
		delta = self.checker.check_expiration()
		print "Domain expires in {} days".format(delta)
		assert delta == self.expiration_date_differential_days

	def test_domain_checker_outside_threshhold(self):
		delta = self.checker.check_expiration(threshhold = 50)
		print "Domain expires in {} days".format(delta)
		assert delta == self.expiration_date_differential_days

	def test_domain_checker_within_threshhold(self):
		with self.assertRaises(DomainExpirationError):
			self.checker.check_expiration(threshhold = 150)

	def test_domain_checker_doesnt_exist(self):
		self.mock_whois_client.query.return_value = None
		with self.assertRaises(WHOISNotFoundError):
			self.checker.check_expiration()
		with self.assertRaises(WHOISNotFoundError):
			self.checker.check_expiration(threshhold = 50)
		with self.assertRaises(WHOISNotFoundError):
			self.checker.check_expiration(threshhold= 150)

