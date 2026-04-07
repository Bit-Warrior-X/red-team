# RedScanner Report — sec-test.skycloud.tw

**Engagement:** Red team engagement plan

Web assessment automation: ProjectDiscovery stack (subfinder, httpx, naabu), nuclei, dalfox, sqlmap, xcrawl3r, waybackurls/gau, nikto, and JS secret patterns (api_leak). Manual phases list follow-up work outside this pipeline.

## Methodology frameworks

- MITRE ATT&CK (Enterprise + Cloud + Recon)
- PTES — Penetration Testing Execution Standard
- OWASP Web Security Testing Guide (WSTG)
- NIST SP 800-115 — Technical Guide for Security Testing

**Scan ID:** 20260407_144352
**Date:** 2026-04-07 14:43
**Duration:** 187.7s
**Modules:** recon, wayback, naabu, nuclei, xss, sqli, api_leak, nikto
**Assets Discovered:** 1

## Summary

| Severity | Count |
|----------|-------|
| Critical | 7 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 3 |

## Manual follow-up (not automated)

### OSINT and passive mapping

- OsintLab / OSINT Framework / web-check / urlscan.io / osint.tools — map metadata and relations
- DNSDumpster + Censys on CDN edge IP; compare DNS completeness vs production baselines
- Synapsint, SubdomainRadar, URLVoid for reputation and exposure
- SpiderFoot, crt.sh — certificate transparency and passive intel

### Active recon and DNS

- MassDNS, dnsx — validate hosts; zone transfer checks where in scope
- subfinder + httpx + naabu — confirm live hosts and ports
- Origin leak / real-IP discovery — correlate with attack platform and CDN roles

### Web and CDN testing (manual)

- Burp Suite Pro + domain_hunter_pro; OWASP ZAP for proxy, spider, fuzzing
- CDN/cache: poisoning, deception, bypass, HTTP smuggling (CL.TE / TE.CL), H2 issues — lab only
- Jaeles, Nmap + NSE, testssl.sh — supplementary to automated nuclei/naabu/nikto
- HExHTTP, 403jump, gobuster — tune wordlists for the target

### Traffic and artifacts

- tcpdump / mirror site → bulk_extractor on PCAP or downloaded tree
- Mantra on JS URL lists: waybackurls|gau → .js → patterns (partially covered by api_leak module)

### Reporting and blue-team handoff

- CVSS v3.1 + business impact, PoC, remediation
- Mend Red-Teaming-Practical-Guide PDF for narrative structure

## Tool / reference links

- https://www.mend.io/wp-content/uploads/2025/09/Red-Teaming-Practical-Guide.pdf
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
- https://github.com/jaeles-project/jaeles
- https://github.com/owasp-amass/amass
- https://github.com/bst04/CyberSources
- https://github.com/wddadk/Offensive-OSINT-Tools


## Vulnerabilities

### 1. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** type
- **Tool:** sqlmap
- **Description:** SQL injection found: [14:46:51] [WARNING] heuristic (basic) test shows that POST parameter 'type' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 2. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** name
- **Tool:** sqlmap
- **Description:** SQL injection found: [14:46:51] [WARNING] heuristic (basic) test shows that POST parameter 'name' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 3. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** email
- **Tool:** sqlmap
- **Description:** SQL injection found: [14:46:52] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 4. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** title
- **Tool:** sqlmap
- **Description:** SQL injection found: [14:46:52] [WARNING] heuristic (basic) test shows that POST parameter 'title' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 5. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** message
- **Tool:** sqlmap
- **Description:** SQL injection found: [14:46:52] [WARNING] heuristic (basic) test shows that POST parameter 'message' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 6. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** unknown
- **Tool:** sqlmap
- **Description:** SQL injection found: [14:46:52] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. Please retry with the switch '--text-only' (along with --technique=BU) as this case looks like a perfect candidate (low textual content along with inability of comparison engine to detect at least one dynamic parameter). If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
- **Remediation:** Use parameterized queries / prepared statements

### 7. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** page
- **Tool:** sqlmap
- **Description:** SQL injection found: [14:46:59] [WARNING] heuristic (basic) test shows that GET parameter 'page' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 8. [INFO] open_port

- **URL:** tcp://sec-test.skycloud.tw:80
- **Tool:** naabu
- **Description:** Responsive port 80/tcp on sec-test.skycloud.tw (naabu)
- **Remediation:** Validate exposure against architecture; restrict firewall/WAF as designed

### 9. [INFO] open_port

- **URL:** tcp://sec-test.skycloud.tw:22
- **Tool:** naabu
- **Description:** Responsive port 22/tcp on sec-test.skycloud.tw (naabu)
- **Remediation:** Validate exposure against architecture; restrict firewall/WAF as designed

### 10. [INFO] open_port

- **URL:** tcp://sec-test.skycloud.tw:443
- **Tool:** naabu
- **Description:** Responsive port 443/tcp on sec-test.skycloud.tw (naabu)
- **Remediation:** Validate exposure against architecture; restrict firewall/WAF as designed
