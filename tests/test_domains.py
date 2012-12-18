from unittest import TestCase
from peace_of_mind import domains

class TestDomains(TestCase):
	def setUp(self):
		pass

	def test_domain_checker_basic(self):
		checker = domains.DomainChecker()
		assert checker
