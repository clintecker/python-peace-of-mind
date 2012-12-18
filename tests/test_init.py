from unittest import TestCase
import peace_of_mind

class TestIinit(TestCase):
	def setUp(self):
		pass

	def test_init(self):
		for submodule in peace_of_mind.__all__:
			m = __import__(submodule, fromlist=['peace_of_mind'])
			assert m
