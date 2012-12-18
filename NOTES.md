* Pagespeed Online API:
	- https://developers.google.com/speed/docs/insights/v1/getting_started
* Mailserver IP Blacklists:
	- `spam-blacklists` library for Spamhaus Zen
	- Not sure for spamcop, should be pretty easy to extend spam-blacklists with bl.spamcop.net
	- Might be easier to just make my own library using this one as a template
* Domain Blacklists:
	- Spamhaus DBL:     http://www.spamhaus.org/dbl/
		- this is very similar to how the above spam blacklists work
	- SafeBrowsing API: https://developers.google.com/safe-browsing/
* Robots.txt parsing "robotparser" library in stdlib
	- Unsure whether or not this validates stuff
* Domain expiration
	- http://code.google.com/p/pywhois/
	- https://github.com/xen/whois
	- https://github.com/Rafiot/Whois-Client
