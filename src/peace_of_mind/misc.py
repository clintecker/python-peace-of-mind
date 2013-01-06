"""
# Miscellanous utilities

This could be home to stuff like robots.txt and sitemaps.xml verification
and other basic checks.  Like code for checking the IP resolution of a
hostname that could be used to notify someone if a DNS record changes.
"""
import socket
from vendor import reppy


class IPResolver(object):
	@staticmethod
	def resolve(host):
		return socket.gethostbyname(host)

class RobotsChecker(object):
	def __init__(self, robots_txt_contents):
		pass
