# CHAATHAN
CHAATHAN — enterprise subdomain takeover scanner. Combines CT scraping, passive DNS, bruteforce/permutation enumeration, HTTP/HTTPS validation and fingerprinting across 50+ cloud services to detect dangling DNS and takeover vectors. SQLite-backed, CLI/TUI, PDF reports. Authorized testing only.

#dive deep

# CHAATHAN v2.0
Advanced Subdomain Takeover Detection Framework

CHAATHAN is an enterprise-grade offensive security framework for large-scale subdomain enumeration, active verification, takeover fingerprint matching, cloud misconfiguration discovery and automatic professional reporting.

This toolkit automates modern subdomain takeover research with a multi-source discovery engine, fingerprint-driven detection logic and persistent data storage.

---

## Key Features

| Capability | Details |
|-----------|---------|
| Enumeration | 15+ data sources (CT Logs, Passive DNS, Web Archives, DNS DBs) |
| Fingerprints | 50+ Cloud / SaaS takeover signatures |
| Verification | Active HTTP/HTTPS probing |
| DB Storage | SQLite scan datasets |
| Reporting | Auto HTML/PDF reporting |
| CLI | Interactive terminal interface |
| Export | JSON / CSV / XML |

---

## Supported Takeover Surfaces

AWS S3, CloudFront  
Azure AppService, Azure CDN  
GitHub Pages, GitLab Pages, Bitbucket, Netlify, Vercel, Render, Railway  
Shopify, WordPress, Zendesk, Intercom  
and many more…

---

## Requirements
bash 4+
curl
dig (dnsutils)
host
sqlite3
wkhtmltopdf (optional for PDF)

## Quick Run

```bash
chmod +x chaathan.sh
./chaathan.sh 

Output

After each scan, results are stored inside:

File	Description
chaathan.db	Full SQLite history
all_subdomains.txt	All discovered subdomains
active_subdomains.txt	Only active DNS/HTTP reachable
vulnerabilities.txt	Verified takeover candidates
chaathan_report_*.pdf	Professional report (if wkhtmltopdf present)

Usage Policy

Use strictly for authorized security research and legal penetration testing.

