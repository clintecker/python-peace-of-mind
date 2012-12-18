from unittest import TestCase
from peace_of_mind import spam

class TestSpam(TestCase):
	def setUp(self):
		pass

	def test_spamhaus_ip_spam_checker_basic(self):
		checker = spam.SpamhausIPSpamChecker()
		assert checker

	def test_spamhaus_domain_spam_checker_basic(self):
		checker = spam.SpamhausDomainSpamChecker()
		assert checker

	def test_spamcop_ip_spam_checker_basic(self):
		checker = spam.SpamcopIPSpamChecker()
		assert checker
