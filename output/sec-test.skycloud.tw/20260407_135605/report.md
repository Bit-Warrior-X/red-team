# RedScanner Report — sec-test.skycloud.tw

## Infrastructure (from red plan)

- **cdn_edge_ip:** 38.60.218.97
- **origin_ip:** 38.60.218.193

**Scan ID:** 20260407_135605
**Date:** 2026-04-07 13:56
**Duration:** 92.9s
**Modules:** recon, nuclei, xss, sqli, api_leak
**Assets Discovered:** 1

## Summary

| Severity | Count |
|----------|-------|
| Critical | 7 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |

## Manual follow-up (not automated)

### OSINT and passive intelligence

- Map the target in dnsdumpster, Censys (also try CDN edge IP), urlscan.io, cylect.io, osint.tools / OSINT framework
- Review February notes: web-check.as93.net, subdomainradar.io, urlvoid for geo/reputation
- Correlate certificate transparency and historical DNS with subfinder/httpx output

### Proxy and manual web testing

- Burp Suite + domain_hunter_pro (January) for domain takeovers and scope
- OWASP ZAP (February): proxy traffic, active scan, manual fuzzing on authenticated flows
- HExHTTP / 403jump when bypassing edge rules — validate findings in staging if available

### Traffic and artifact analysis

- Capture PCAP or wget mirror, run bulk_extractor on captures or mirrored content (February)
- Mantra-style JS review: waybackurls|gau → grep .js → secret patterns (partially automated by api_leak module)

### Further reading

- OWASP Amass / Dome with API keys when passive sources dry up
- CyberSources & Offensive-OSINT-Tools (February backlog)
- Mend Red Teaming Practical Guide (PDF from January note)

## Tool / reference links

- https://github.com/projectdiscovery/subfinder
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/naabu
- https://github.com/projectdiscovery/nuclei
- https://github.com/hahwul/dalfox
- https://github.com/sqlmapproject/sqlmap
- https://github.com/hueristiq/xcrawl3r
- https://github.com/tomnomnom/waybackurls
- https://github.com/lc/gau
- https://github.com/tomnomnom/assetfinder
- https://github.com/sullo/nikto
- https://github.com/brosck/mantra
- https://github.com/bit4woo/domain_hunter_pro
- https://github.com/bst04/CyberSources
- https://github.com/wddadk/Offensive-OSINT-Tools


## Vulnerabilities

### 1. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** type
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:57:21] [WARNING] heuristic (basic) test shows that POST parameter 'type' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 2. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** name
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:57:22] [WARNING] heuristic (basic) test shows that POST parameter 'name' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 3. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** email
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:57:22] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 4. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** title
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:57:22] [WARNING] heuristic (basic) test shows that POST parameter 'title' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 5. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** message
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:57:23] [WARNING] heuristic (basic) test shows that POST parameter 'message' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 6. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** unknown
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:57:23] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. Please retry with the switch '--text-only' (along with --technique=BU) as this case looks like a perfect candidate (low textual content along with inability of comparison engine to detect at least one dynamic parameter). If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
- **Remediation:** Use parameterized queries / prepared statements

### 7. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** page
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:57:29] [WARNING] heuristic (basic) test shows that GET parameter 'page' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements
