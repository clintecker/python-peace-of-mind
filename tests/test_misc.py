from unittest import TestCase
from peace_of_mind import misc

class TestMisc(TestCase):
	def setUp(self):
		pass

	def test_ip_resolver_basic(self):
		checker = misc.IPResolver()
		assert checker

	def test_robots_txt_validator_basic(self):
		data = """# robots.txt for http://www.example.com/

User-agent: *
Disallow: /cyberworld/map/ # This is an infinite virtual URL space
Disallow: /tmp/ # these will soon disappear
Disallow: /foo.html"""

		checker = misc.RobotsChecker.init_from_string(data)
		print checker.allowed('/cool.html?pow=cool')
		assert checker
