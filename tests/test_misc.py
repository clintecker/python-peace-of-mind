from unittest import TestCase
from peace_of_mind import misc

class TestMisc(TestCase):
	def setUp(self):
		pass

	def test_ip_resolver_basic(self):
		checker = misc.IPResolver()
		assert checker

	def test_robots_txt_validator_basic(self):
		checker = misc.RobotsChecker("")
		assert checker
