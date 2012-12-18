# Domain Validation
#
# This file should define a DomainChecker class that, at the very minimum,
# would be capable of determining a domain's expiration date and given a
# threshold, throw a warning or not.

class DomainChecker(object):
	def __init__(self, domain_name):
		self.domain_name = domain_name

