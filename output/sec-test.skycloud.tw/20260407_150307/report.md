# RedScanner Report — sec-test.skycloud.tw

**Engagement:** Red team engagement plan

Web assessment automation: ProjectDiscovery stack (subfinder, httpx, naabu), nuclei, dalfox, sqlmap, xcrawl3r, waybackurls/gau, nikto, and JS secret patterns (api_leak). Manual phases list follow-up work outside this pipeline.

## Methodology frameworks

- MITRE ATT&CK (Enterprise + Cloud + Recon)
- PTES — Penetration Testing Execution Standard
- OWASP Web Security Testing Guide (WSTG)
- NIST SP 800-115 — Technical Guide for Security Testing

**Scan ID:** 20260407_150307
**Date:** 2026-04-07 15:03
**Duration:** 337.8s
**Modules:** recon, wayback, naabu, nuclei, xss, sqli, api_leak, nikto
**HTTP assets (httpx):** 1

## Summary

| Severity | Count |
|----------|-------|
| Critical | 7 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 3 |

## Attack surface

- **Domains / hostnames:** 1
- **Open ports (naabu):** 3
- **Crawled URLs (recon):** 618
- **Historical URLs (wayback/gau):** 0
- **Full scan URL list (nuclei + surface):** 1

### Domains

- `sec-test.skycloud.tw`


### Open ports

| Host | Port | Protocol |
|------|------|----------|
| sec-test.skycloud.tw | 443 | tcp |
| sec-test.skycloud.tw | 80 | tcp |
| sec-test.skycloud.tw | 22 | tcp |


### HTTP services (httpx)

| URL | IP | Port | Status | Title | Tech |
|-----|-----|------|--------|-------|------|
| `http://sec-test.skycloud.tw` | sec-test.skycloud.tw | 80 | 200 | 騰雲運算｜CDN加速｜DDoS防禦 | Bootstrap:4.6, Google Analytics, Google Tag Manager, Laravel, PHP:7.4.33 |


### Crawled resources (links)

- `http://localhost/`
- `http://localhost/about`
- `http://localhost/background`
- `http://localhost/cn/`
- `http://localhost/cn/about`
- `http://localhost/cn/background`
- `http://localhost/cn/contact`
- `http://localhost/cn/news`
- `http://localhost/cn/news/10`
- `http://localhost/cn/news/100`
- `http://localhost/cn/news/101`
- `http://localhost/cn/news/102`
- `http://localhost/cn/news/103`
- `http://localhost/cn/news/104`
- `http://localhost/cn/news/105`
- `http://localhost/cn/news/106`
- `http://localhost/cn/news/107`
- `http://localhost/cn/news/108`
- `http://localhost/cn/news/109`
- `http://localhost/cn/news/11`
- `http://localhost/cn/news/110`
- `http://localhost/cn/news/111`
- `http://localhost/cn/news/112`
- `http://localhost/cn/news/113`
- `http://localhost/cn/news/114`
- `http://localhost/cn/news/115`
- `http://localhost/cn/news/116`
- `http://localhost/cn/news/117`
- `http://localhost/cn/news/118`
- `http://localhost/cn/news/119`
- `http://localhost/cn/news/12`
- `http://localhost/cn/news/120`
- `http://localhost/cn/news/121`
- `http://localhost/cn/news/122`
- `http://localhost/cn/news/123`
- `http://localhost/cn/news/124`
- `http://localhost/cn/news/125`
- `http://localhost/cn/news/126`
- `http://localhost/cn/news/127`
- `http://localhost/cn/news/128`
- `http://localhost/cn/news/129`
- `http://localhost/cn/news/13`
- `http://localhost/cn/news/130`
- `http://localhost/cn/news/131`
- `http://localhost/cn/news/132`
- `http://localhost/cn/news/133`
- `http://localhost/cn/news/134`
- `http://localhost/cn/news/135`
- `http://localhost/cn/news/136`
- `http://localhost/cn/news/137`
- `http://localhost/cn/news/138`
- `http://localhost/cn/news/139`
- `http://localhost/cn/news/14`
- `http://localhost/cn/news/140`
- `http://localhost/cn/news/142`
- `http://localhost/cn/news/143`
- `http://localhost/cn/news/144`
- `http://localhost/cn/news/145`
- `http://localhost/cn/news/146`
- `http://localhost/cn/news/147`
- `http://localhost/cn/news/148`
- `http://localhost/cn/news/149`
- `http://localhost/cn/news/15`
- `http://localhost/cn/news/150`
- `http://localhost/cn/news/151`
- `http://localhost/cn/news/152`
- `http://localhost/cn/news/153`
- `http://localhost/cn/news/154`
- `http://localhost/cn/news/155`
- `http://localhost/cn/news/156`
- `http://localhost/cn/news/157`
- `http://localhost/cn/news/158`
- `http://localhost/cn/news/159`
- `http://localhost/cn/news/16`
- `http://localhost/cn/news/160`
- `http://localhost/cn/news/161`
- `http://localhost/cn/news/162`
- `http://localhost/cn/news/163`
- `http://localhost/cn/news/164`
- `http://localhost/cn/news/165`
- `http://localhost/cn/news/166`
- `http://localhost/cn/news/167`
- `http://localhost/cn/news/168`
- `http://localhost/cn/news/169`
- `http://localhost/cn/news/17`
- `http://localhost/cn/news/170`
- `http://localhost/cn/news/18`
- `http://localhost/cn/news/19`
- `http://localhost/cn/news/2`
- `http://localhost/cn/news/20`
- `http://localhost/cn/news/21`
- `http://localhost/cn/news/22`
- `http://localhost/cn/news/23`
- `http://localhost/cn/news/24`
- `http://localhost/cn/news/25`
- `http://localhost/cn/news/27`
- `http://localhost/cn/news/28`
- `http://localhost/cn/news/3`
- `http://localhost/cn/news/31`
- `http://localhost/cn/news/34`
- `http://localhost/cn/news/35`
- `http://localhost/cn/news/36`
- `http://localhost/cn/news/37`
- `http://localhost/cn/news/38`
- `http://localhost/cn/news/39`
- `http://localhost/cn/news/4`
- `http://localhost/cn/news/40`
- `http://localhost/cn/news/41`
- `http://localhost/cn/news/42`
- `http://localhost/cn/news/43`
- `http://localhost/cn/news/44`
- `http://localhost/cn/news/45`
- `http://localhost/cn/news/46`
- `http://localhost/cn/news/47`
- `http://localhost/cn/news/48`
- `http://localhost/cn/news/49`
- `http://localhost/cn/news/5`
- `http://localhost/cn/news/50`
- `http://localhost/cn/news/51`
- `http://localhost/cn/news/52`
- `http://localhost/cn/news/54`
- `http://localhost/cn/news/55`
- `http://localhost/cn/news/56`
- `http://localhost/cn/news/57`
- `http://localhost/cn/news/58`
- `http://localhost/cn/news/59`
- `http://localhost/cn/news/6`
- `http://localhost/cn/news/61`
- `http://localhost/cn/news/62`
- `http://localhost/cn/news/63`
- `http://localhost/cn/news/64`
- `http://localhost/cn/news/65`
- `http://localhost/cn/news/67`
- `http://localhost/cn/news/68`
- `http://localhost/cn/news/69`
- `http://localhost/cn/news/7`
- `http://localhost/cn/news/70`
- `http://localhost/cn/news/71`
- `http://localhost/cn/news/72`
- `http://localhost/cn/news/73`
- `http://localhost/cn/news/74`
- `http://localhost/cn/news/75`
- `http://localhost/cn/news/76`
- `http://localhost/cn/news/77`
- `http://localhost/cn/news/78`
- `http://localhost/cn/news/79`
- `http://localhost/cn/news/8`
- `http://localhost/cn/news/81`
- `http://localhost/cn/news/82`
- `http://localhost/cn/news/83`
- `http://localhost/cn/news/84`
- `http://localhost/cn/news/85`
- `http://localhost/cn/news/86`
- `http://localhost/cn/news/87`
- `http://localhost/cn/news/88`
- `http://localhost/cn/news/89`
- `http://localhost/cn/news/9`
- `http://localhost/cn/news/90`
- `http://localhost/cn/news/91`
- `http://localhost/cn/news/92`
- `http://localhost/cn/news/93`
- `http://localhost/cn/news/94`
- `http://localhost/cn/news/95`
- `http://localhost/cn/news/96`
- `http://localhost/cn/news/97`
- `http://localhost/cn/news/98`
- `http://localhost/cn/news/99`
- `http://localhost/cn/note`
- `http://localhost/cn/price/advanced_cloud/hk`
- `http://localhost/cn/price/advanced_cloud/tw`
- `http://localhost/cn/price/cdn-cn`
- `http://localhost/cn/price/cdn-global`
- `http://localhost/cn/price/cloud/hk`
- `http://localhost/cn/price/cloud/jp`
- `http://localhost/cn/price/cloud/tw`
- `http://localhost/cn/price/ddos`
- `http://localhost/cn/price/meeting`
- `http://localhost/cn/price/outsourcing`
- `http://localhost/cn/price/server`
- `http://localhost/cn/privacy`
- `http://localhost/cn/product/advanced_cloud`
- `http://localhost/cn/product/cdn`
- `http://localhost/cn/product/ddos`
- `http://localhost/cn/product/server`
- `http://localhost/cn/terms`
- `http://localhost/contact`
- `http://localhost/jp/`
- `http://localhost/jp/about`
- `http://localhost/jp/background`
- `http://localhost/jp/contact`
- `http://localhost/jp/news`
- `http://localhost/jp/news/10`
- `http://localhost/jp/news/100`
- `http://localhost/jp/news/101`
- `http://localhost/jp/news/102`
- `http://localhost/jp/news/103`
- `http://localhost/jp/news/104`
- `http://localhost/jp/news/105`
- `http://localhost/jp/news/106`
- `http://localhost/jp/news/107`
- `http://localhost/jp/news/108`
- `http://localhost/jp/news/109`
- `http://localhost/jp/news/11`
- `http://localhost/jp/news/110`
- `http://localhost/jp/news/111`
- `http://localhost/jp/news/112`
- `http://localhost/jp/news/113`
- `http://localhost/jp/news/114`
- `http://localhost/jp/news/115`
- `http://localhost/jp/news/116`
- `http://localhost/jp/news/117`
- `http://localhost/jp/news/118`
- `http://localhost/jp/news/119`
- `http://localhost/jp/news/12`
- `http://localhost/jp/news/120`
- `http://localhost/jp/news/121`
- `http://localhost/jp/news/122`
- `http://localhost/jp/news/123`
- `http://localhost/jp/news/124`
- `http://localhost/jp/news/125`
- `http://localhost/jp/news/126`
- `http://localhost/jp/news/127`
- `http://localhost/jp/news/128`
- `http://localhost/jp/news/129`
- `http://localhost/jp/news/13`
- `http://localhost/jp/news/130`
- `http://localhost/jp/news/131`
- `http://localhost/jp/news/132`
- `http://localhost/jp/news/133`
- `http://localhost/jp/news/134`
- `http://localhost/jp/news/135`
- `http://localhost/jp/news/136`
- `http://localhost/jp/news/137`
- `http://localhost/jp/news/138`
- `http://localhost/jp/news/139`
- `http://localhost/jp/news/14`
- `http://localhost/jp/news/140`
- `http://localhost/jp/news/142`
- `http://localhost/jp/news/143`
- `http://localhost/jp/news/144`
- `http://localhost/jp/news/145`
- `http://localhost/jp/news/146`
- `http://localhost/jp/news/147`
- `http://localhost/jp/news/148`
- `http://localhost/jp/news/149`
- `http://localhost/jp/news/15`
- `http://localhost/jp/news/150`
- `http://localhost/jp/news/151`
- `http://localhost/jp/news/152`
- `http://localhost/jp/news/153`


*… and 368 more (see report.json for full lists).*

### URLs in scanner scope

- `http://sec-test.skycloud.tw`


### Query parameters observed

| Parameter | Occurrences | Example URLs | Tools |
|-----------|-------------|--------------|-------|
| `email` | 1 | `http://sec-test.skycloud.tw` | sqlmap |
| `message` | 1 | `http://sec-test.skycloud.tw` | sqlmap |
| `name` | 1 | `http://sec-test.skycloud.tw` | sqlmap |
| `page` | 1 | `http://sec-test.skycloud.tw` | sqlmap |
| `title` | 1 | `http://sec-test.skycloud.tw` | sqlmap |
| `type` | 1 | `http://sec-test.skycloud.tw` | sqlmap |
| `unknown` | 1 | `http://sec-test.skycloud.tw` | sqlmap |


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
- **Description:** SQL injection found: [15:08:21] [WARNING] heuristic (basic) test shows that POST parameter 'type' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 2. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** name
- **Tool:** sqlmap
- **Description:** SQL injection found: [15:08:22] [WARNING] heuristic (basic) test shows that POST parameter 'name' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 3. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** email
- **Tool:** sqlmap
- **Description:** SQL injection found: [15:08:22] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 4. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** title
- **Tool:** sqlmap
- **Description:** SQL injection found: [15:08:22] [WARNING] heuristic (basic) test shows that POST parameter 'title' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 5. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** message
- **Tool:** sqlmap
- **Description:** SQL injection found: [15:08:23] [WARNING] heuristic (basic) test shows that POST parameter 'message' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 6. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** unknown
- **Tool:** sqlmap
- **Description:** SQL injection found: [15:08:23] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. Please retry with the switch '--text-only' (along with --technique=BU) as this case looks like a perfect candidate (low textual content along with inability of comparison engine to detect at least one dynamic parameter). If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
- **Remediation:** Use parameterized queries / prepared statements

### 7. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** page
- **Tool:** sqlmap
- **Description:** SQL injection found: [15:08:32] [WARNING] heuristic (basic) test shows that GET parameter 'page' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 8. [INFO] open_port

- **URL:** tcp://sec-test.skycloud.tw:443
- **Tool:** naabu
- **Description:** Responsive port 443/tcp on sec-test.skycloud.tw (naabu)
- **Remediation:** Validate exposure against architecture; restrict firewall/WAF as designed

### 9. [INFO] open_port

- **URL:** tcp://sec-test.skycloud.tw:80
- **Tool:** naabu
- **Description:** Responsive port 80/tcp on sec-test.skycloud.tw (naabu)
- **Remediation:** Validate exposure against architecture; restrict firewall/WAF as designed

### 10. [INFO] open_port

- **URL:** tcp://sec-test.skycloud.tw:22
- **Tool:** naabu
- **Description:** Responsive port 22/tcp on sec-test.skycloud.tw (naabu)
- **Remediation:** Validate exposure against architecture; restrict firewall/WAF as designed
