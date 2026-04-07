# RedScanner Report — sec-test.skycloud.tw

**Scan ID:** 20260407_132930
**Date:** 2026-04-07 13:29
**Duration:** 221.1s
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

## Vulnerabilities

### 1. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** type
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:32:08] [WARNING] heuristic (basic) test shows that POST parameter 'type' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 2. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** name
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:32:08] [WARNING] heuristic (basic) test shows that POST parameter 'name' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 3. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** email
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:32:09] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 4. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** title
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:32:09] [WARNING] heuristic (basic) test shows that POST parameter 'title' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 5. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** message
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:32:09] [WARNING] heuristic (basic) test shows that POST parameter 'message' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements

### 6. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** unknown
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:32:09] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. Please retry with the switch '--text-only' (along with --technique=BU) as this case looks like a perfect candidate (low textual content along with inability of comparison engine to detect at least one dynamic parameter). If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
- **Remediation:** Use parameterized queries / prepared statements

### 7. [CRITICAL] sqli

- **URL:** http://sec-test.skycloud.tw
- **Parameter:** page
- **Tool:** sqlmap
- **Description:** SQL injection found: [13:32:51] [WARNING] heuristic (basic) test shows that GET parameter 'page' might not be injectable
- **Remediation:** Use parameterized queries / prepared statements
