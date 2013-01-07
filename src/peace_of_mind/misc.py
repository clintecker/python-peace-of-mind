"""
# Miscellanous utilities

This could be home to stuff like robots.txt and sitemaps.xml verification
and other basic checks.  Like code for checking the IP resolution of a
hostname that could be used to notify someone if a DNS record changes.
"""
import socket
import urllib2
from vendor import reppy


class IPResolver(object):
	@staticmethod
	def resolve(host):
		return socket.gethostbyname(host)

class RobotsChecker(object):
	def __init__(self):
		self._reppy = None


	@classmethod
	def init_from_robots_url(cls, robots_url):
		r = cls()
		r._reppy = reppy.fetch(robots_url)
		return r


	@classmethod
	def init_from_site_url(cls, page_url):
		r = cls()
		r._reppy = reppy(url=page_url)
		return r


	@classmethod
	def init_from_string(cls, robots_string):
		r = cls()
		r._reppy = reppy.parse(robots_string)
		return r

	def allowed(self, url):
		return self._reppy.allowed(url, '*')
