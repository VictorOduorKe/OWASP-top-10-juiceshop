# Juice Shop Penetration Test Report
**Tester:** Victor Oduor  
**Date:** 2026-06-17  
**Target:** OWASP Juice Shop - v19.3.1 @ http://localhost:3000 (local Docker)  
**Scope:** Local instance only. Out of scope: host OS, Docker daemon, DoS testing.

## Executive Summary
These are the findings from the penetration test of OWASP Juice Shop - v19.3.1 @ http://localhost:3000 (local Docker) conducted on 2026-06-17. The assessment was scoped exclusively to the local web application instance. These findings are categorized in accordance with the OWASP Top 10 security standards and are ordered from most critical to least critical by CVSS v3.1 score.

---
## Findings Summary Table
| # | Finding | OWASP Category | Severity | CVSS v3.1 Score | CVSS Vector |
|---|---------|----------------|----------|-----------------|-------------|
| 1 | SQL Injection in Login Endpoint | A03:2021 – Injection | Critical | 9.8 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| 2 | Insecure Direct Object Reference (IDOR) on Baskets | A01:2021 – Broken Access Control | Medium | 6.5 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| 3 | Forced Browsing & Information Disclosure via `/ftp` | A05:2021 – Security Misconfiguration | High | 7.5 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |

## Attack Chain Narrative
An unauthenticated external attacker can chain these vulnerabilities to achieve a complete compromise of customer purchase history, administrative configurations, and internal coupon codes.

```mermaid
graph TD
    A[Unauthenticated Attacker] -->|Registers standard account| B(Obtain Low-Privileged JWT)
    B -->|Exploits Basket IDOR - Finding 2| C(Harvest user baskets & Admin's basket metadata)
    C -->|Reveals /ftp directory & backup file path| D(Target /ftp folder)
    D -->|Forced Browsing & Whitelist Bypass - Finding 3| E(Download coupons_2013.md.bak)
    E -->|Exposes source/SQL query construction comments| F(Identify Login SQLi Vulnerability)
    F -->|Exploits SQL Injection - Finding 1| G(Seize Administrator Session & Full System Control)
```

1. **Phase 1 (Initial Access & IDOR Enumeration):** The attacker registers a standard, low-privileged customer account (open to the public via the signup interface) to obtain a valid JWT. They then exploit the Insecure Direct Object Reference (IDOR) vulnerability (Finding 2) on the `GET /rest/basket/{id}` endpoint. By iterating the basket ID parameter, they scrape the purchase histories of all 24 registered users.
2. **Phase 2 (Information Disclosure & Path Discovery):** While analyzing the administrator's basket (ID 1), the attacker discovers items or checkout metadata referencing internal storage structures and backup paths, specifically pointing to the existence of the restricted `/ftp` directory.
3. **Phase 3 (Forced Browsing & Whitelist Bypass):** Using this path, the attacker performs forced browsing on the `/ftp` directory (Finding 3) which is misconfigured to allow directory listing. They locate the backup file `coupons_2013.md.bak` and bypass the server's extension whitelist check using a double-URL-encoded null byte (`%2500.md`) to download it.
4. **Phase 4 (SQL query structure leak & Administrative Takeover):** Within the downloaded backup file, the attacker finds developer comments detailing the database query structure for the login routing, exposing that the query is constructed using raw string concatenation. Armed with this knowledge of the exact query logic, the attacker executes a SQL Injection attack (Finding 1) on the `/rest/user/login` endpoint using `' OR 1=1--` to bypass authentication and log in directly as the administrator, completing the full system takeover.
5. **Phase 5 (Business Impact & Records Exposed):** The successful execution of this chained attack results in the unauthorized disclosure of PII for all 24 registered users, exposure of proprietary business logic, leak of historical coupon code structures, and administrative-level control over the application's database.

---

## Finding 1 — A03:2021 — SQL Injection in Login Endpoint
**Severity:** Critical  
**CVSS v3.1:** 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)  
**Endpoint:** `POST /rest/user/login`

### Description
The application fails to properly sanitize the `email` field on the login form, allowing an attacker to inject SQL commands that alter the structure of the database query.

### Reproduction
1. Navigate to `http://localhost:3000/#/login`
2. Enter email: `' OR 1=1--` (with a trailing space)
3. Enter password: `anything`
4. Click Log in, or execute the following `curl` command to receive the administrator token:

```bash
curl -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1-- ","password":"x"}'
```

### Evidence
![Admin Login Success](./screenshots/Screenshot_2026-06-17_09_49_53.png)
*Figure 1: Application returns administrator session token and login data.*

### Root Cause
The database handler concatenates user-supplied email input directly into the SQL query string instead of executing a parameterized query. The injected `--` comments out the password evaluation check, and `OR 1=1` forces the clause to evaluate to true, defaulting to the first record in the database table (the administrator).

### Remediation
- Use parameterized queries or ORM equivalents (e.g., Sequelize's replacement bindings) to ensure inputs are treated strictly as data rather than SQL executable commands.
- Implement strict input validation on the email parameter using an RFC 5322-compliant regular expression before it reaches the SQL engine.

### References
- OWASP A03:2021 — Injection
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

---

## Finding 2 — A01:2021 — Broken Access Control (Basket IDOR)
**Severity:** Medium  
**CVSS v3.1:** 6.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`)  
**Endpoint:** `GET /rest/basket/{id}`

> [!NOTE]
> **CVSS Vector Justification:** Because the `/rest/basket/{id}` route enforces authentication, the attacker must possess a valid JSON Web Token (JWT) to query the endpoint, which warrants **PR:L** (Privileges Required: Low). However, because registration is public and self-service, any external user can register a low-privileged account instantly. If your threat model considers self-registration equivalent to no barrier, the vector can be evaluated as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5 - High).

### Description
The application does not validate that the user requesting the shopping basket owns the corresponding basket ID. This allows an authenticated standard user to view arbitrary user baskets by modifying the ID parameter in the request path.

### Reproduction
1. Authenticate to the application as a normal user.
2. Intercept or construct a GET request to view your own basket (e.g., basket ID 1):
   ```bash
   curl -k GET http://localhost:3000/rest/basket/1 -H "Authorization: Bearer <user_token>"
   ```
3. Alter the basket ID parameter to `2` to view details of another customer's basket:
   ```bash
   curl -k GET http://localhost:3000/rest/basket/2 -H "Authorization: Bearer <user_token>"
   ```

### Evidence
![Own Basket View](./screenshots/Screenshot_2026-06-17_10_23_03.png)
*Figure 2: Authenticated user viewing their own shopping basket.*

![Unauthorized Basket View](./screenshots/Screenshot_2026-06-17_10_24_59.png)
*Figure 3: Accessing another user's basket by modifying the basket ID.*

### Root Cause
Modern Sequelize implementation of basket fetching retrieves basket resources based directly on the path parameter without validating if the JWT's embedded `bid` matches the path's `{id}`.

### Remediation
- Enforce strict server-side authorization checks on the `/rest/basket/{id}` endpoint to ensure the user ID in the JWT matches the `UserId` associated with the requested basket.
- Avoid using predictable, sequential integer keys for basket paths; utilize UUIDs or session-bound paths where appropriate.

### References
- OWASP A01:2021 — Broken Access Control
- CWE-284: Improper Access Control

---

## Finding 3 — A05:2021 — Security Misconfiguration (Forced Browsing / Sensitive files via /ftp)
**Severity:** High  
**CVSS v3.1:** 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)  
**Endpoint:** `GET /ftp`

### Description
The server exposes directory listing and download capability for the `/ftp` route, exposing internal backup markdown documents and configuration files. Additionally, restricted file extension checks can be bypassed using URL-encoded null bytes.

### Verification of Bypass on v19.3.1
The null byte bypass remains fully functional on OWASP Juice Shop v19.3.1. When requesting `http://localhost:3000/ftp/coupons_2013.md.bak%2500.md`, the web server receives the request, processes the `.md` extension check, but the low-level file system read API truncates the path at the null character, outputting the contents of `coupons_2013.md.bak`.

### Reproduction
1. Direct the browser to `http://localhost:3000/ftp` or run:
   ```bash
   curl -k GET http://localhost:3000/ftp
   ```
2. Request a restricted backup file (e.g. `coupons_2013.md.bak`) by bypassing extension validation with a double-encoded null byte:
   ```bash
   curl http://localhost:3000/ftp/coupons_2013.md.bak%2500.md
   ```

### Evidence
![Exposed FTP Directory](./screenshots/Screenshot_2026-06-17_10_30_19.png)
*Figure 4: Active directory listing displaying files in the /ftp directory.*

**Raw Response Body Content (Retrieved from v19.3.1 Instance):**
```text
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

![Exposed Sensitive File Content](./screenshots/Screenshot_2026-06-17_10_30_51.png)
*Figure 5: Successful bypass and download of coupons_2013.md.bak exposing reversible coupon structures.*

### Root Cause
The application server configuration enables directory browsing on the `/ftp` path. Furthermore, the file download validation logic is vulnerable to null-byte injection (`%00` or double-encoded `%2500`), which causes the file system API to truncate the path string and serve the `.bak` file while bypassing the application's extension whitelist check.

### Remediation
- Disable directory browsing on the web server config or the static directory serving route.
- Restrict sensitive files and backups from being kept in the web-root directories.
- Clean and sanitize input file path parameters by rejecting null bytes (`%00`, `\0`) and path traversal sequences (`../`).

### References
- OWASP A05:2021 — Security Misconfiguration
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

---

## Recommendations (Prioritized)
1. **Immediate:** Upgrade login logic to use parameterized queries (Finding 1) to break the initial entry point of the attack chain.
2. **High:** Enforce authorization checks on `GET /rest/basket/{id}` (Finding 2) to protect customer PII from exposure.
3. **Medium:** Disable directory listing and restrict access to the `/ftp` directory (Finding 3), ensuring sensitive file extensions cannot be bypassed.

## Regulatory Context
Under Kenya's Data Protection Act 2019, the unauthorized exposure of customer PII (Finding 2) constitutes a personal data breach. Pursuant to Section 43, the data controller is required to notify the Office of the Data Protection Commissioner (ODPC) within 72 hours of identification. Under Section 72, non-compliance or failure to protect user data carries statutory penalties of up to KES 5,000,000 or 1% of the annual turnover, whichever is lower.

## Appendix A — Tooling
- Burp Suite Community Edition (v147.0.7727.101)
- curl (v8.5.0)
- OWASP Juice Shop Local Docker Container (v19.3.1)