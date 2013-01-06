# Peace of Mind
Clint Ecker <me@clintecker>
---------------------------

This is a set of tools, arranged as a single library that helps someone keep
tabs on their core digital assets.  Losing your domain name or letting your
SSL certificates expire can lead to hundreds if not thousands of dollars in
damage to your bottom line in the best cast.  In the worst care your customers
may lose faith in your company or brand.

These tools will power a subscription web service that will give individuals,
startups, and enterprise customers full faith that their assets are being
monitored and will be alerted, ahead of time if possible, that their
core assets are at risk or have been altered.

### License

Peace of Mind was writted by Clint Ecker <me@clintecker.com> and is
licensed under the MIT license (see LICENSE file).

### Installing

Please see `CONTRIBUTING.md`

### Documentation

Documentation lives in ./docs/ as reStructuredText files

### Tools that exist now:

* **Validate domain records**: Detect when a domain will expire or when contact information is altered.
* **Validate SSL certificates**: Expiration dates, host matching, bit levels.
	- Future plans could be detecting if a certificate is vulnerable to known and newly discovered exploits.
* **Malware & Phishing Detection**: Know the minute Google detects malware or phishing scams on domains you have control over.  Do you resell web space or allow user hosted content on your domains?  Know about possible issues as soon as possible.  Once your site gets on this list, Google listings and Google's Chrome Browser will begin blocking your site.

### Future tools:

* **Verify that your mail servers are not blacklisted**: Query popular DNSBLs like Spamhaus and SpamCop to determine if the IP addresses that power your company email have been added to any Spam blacklists.  Know about potential delivery problems before people start comaplining.
* **Verify that your domains are not blacklisted**: Query SpamHaus's DBL to determine if your domains are blacklisted.
* **Validate your robots.txt files**: Detect if your files are not valid, are not optimized, or ineffective.  Save hours of time fiddling with weird formats without knowing if your changes are making a difference.
* **Pagespeed results**: Get a rough idea of the performance of your webpage as calculated by Google.  Google uses this information to weight your page rankings.  Faster sites are ranked higher.  We can detect when your homepage PageSpeed becomes better or worse.
* **Determine Various SEO stats**: Alexa ranking, Google PageRank -- know when they change
* **Check Filtering Proxy Blacklists**: Know if a popular filtering proxy (SafeSquid, Websense, NetNanny, Barracuda) has listed your domains, preventing corporate or private access to your websites.
