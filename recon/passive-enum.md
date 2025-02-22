# Passive Enumeration


## Intro

Another term for this is OSINT: Open-source Intelligence. This is *"the process of collecting openly-available information about a target, generally without any direct interaction with that target"*.

That *generally* part is because the exact level of interaction with the target is open to interpratation:
- **Strict** passive: No interaction with the target systems or servers, but can rely on third parties for information e.g. whois, shodan, google hacking, social media etc.
- **Loose** passive: Limited interaction with target systems, imitating the behaviour of a non-malicious legitimate user (e.g. browsing through a website's content and clicking links)

Goals of passive enumeration:
- Obtain information which clarifies or expands an *attack surface*
- Assist in conducting successful phishing campaigns
- Supplements other pentesting techniques such as password guessing


## Whois

A service which reveals information about domain name registrations. This includes:
- Domain registrar
- Creation / Expiration date
- Domain owner's information (can be hidden in some cases)
- IP address allocation
- Name servers for DNS
- Geolocation

Example command (where `<whois_host>` can be a domain name or IP address):
```
whois <domain> [-h <whois_host>]
```

Can also do reverse whois lookup assuming we have an IP:
```
whois <IP> [-h <whois_host>]
```
Tends to give more info such as domain hosts.


## Google Hacking

Using clever search strings, operators and filters for the creative refinement of search queries. This is in the hopes of uncovering critical information, vulnerabilities and misconfigurations within websites.

Iterative process: start with broad query and narrow down using operators to remove uninteresting results.

Example operators:
- `site:<site_domain_name>`
- `filetype:<type>` e.g. `txt` - might reveal cool stuff like `robots.txt`
- `ext:<extension>` e.g. `php`, `py`, `xml`
- `intitle:<string>` - `<string>` might need to be enclosed with quotes (e.g. intitle:"index of" "parent directory")
- `"<string>"` to find a specific string in the page body (note the quotes)



You can remove items from results using filters above by putting a `-` before it, e.g.:
```
site:reddit.com -filetype:html
```
will yield all reddit pages that are not HTML or
```
site:example.com -site:subdomain.example.com
```
gives you anything in the `example.com` domain except ro anything in the `subdomain.example.com` subdomain of the domain.

Visit Google Hacking Database (GHDB) for more info: https://www.exploit-db.com/google-hacking-database


## Netcraft

Internet service company with info gathering functions such as:
- Technology discovery (server applications such as Apache/IIS, OS, frameworks, CST/SST)
- IP delegation info
- Subdomain enumeration
- Various other network details, like similar sites in same netblock

See https://searchdns.netcraft.com/, search for site and view site report


## Open Source Codebase

Look at repos for interesting stuff like technology composition, hidden/obscure functionality etc. might even find some secrets.

Similar to Google Hacking, each source code repo provider has its own query language. GitHub's for example:
- `path:<string>` search for `<string>` in file name
- `owner:<string>`

On larger repos, use something like Gitleaks or other secrets scanning tool (same kind that it used in CI/CD), but remember these won't be 100% accurate in findings and might miss stuff, so try to manually inspect anyway


## Shodan

Shodan is a search-engine like service for things beyond just web pages, e.g. IoT devices and other network devices connected to the internet, such as a router. But it *can* also include web pages.

You need an account with them. Free accounts are limited and paid accounts get more.

Has a query language, such as `hostname:example.com`. We can be more specific about the kind of service we are looking for as well, such as `hostname:example.com port:"22"` - this might be able to give us details about the SSH service being hosted here, such as the exact OpenSSH version or other service info.

Shodan can also reveal if there are any associated known vulnerabilities with the technologies and services running on the host.


## Security Headers and Cryptography

This can be considered passive recon if we are using intermediary services which have already done the inspection work for us.

For security headers, visit https://securityheaders.com/

For cryptography for TLS/SSL, visit Qualys SSL Labs: https://www.ssllabs.com/ssltest/

Services like these require manual analysis to ensure the findings are in fact vulnerabilities relative to the context.