# OWASP API Security Top 10 (2023) - Core Vulnerabilities

The OWASP API Security Top 10 highlights the most critical security risks to modern APIs. Understanding these vulnerabilities is the first step toward building secure microservices.

---

## API1:2023 - Broken Object Level Authorization (BOLA)
**Also known as:** Insecure Direct Object Reference (IDOR)
**The Flaw:** The API endpoint receives an ID from the client (e.g., `/api/users/1234/financials`) and queries the database using *only* that ID. It fails to check if the user making the request actually has authorization to view object `1234`.
**Impact:** Attackers can iterate through IDs (1235, 1236) and access data belonging to other users, leading to massive data breaches.

## API2:2023 - Broken Authentication
**The Flaw:** Authentication mechanisms are implemented incorrectly. This includes allowing weak passwords, not enforcing rate limiting on login endpoints (allowing credential stuffing/brute force), sending tokens in URLs, or failing to validate JWT signatures properly.
**Impact:** Attackers can assume the identity of legitimate users or administrators.

## API3:2023 - Broken Object Property Level Authorization (BOPLA)
**The Flaw:** Combining Mass Assignment and Excessive Data Exposure. The API exposes properties of an object that the user shouldn't see (e.g., returning a full `User` object including password hashes and internal flags to the frontend) OR allows the user to update properties they shouldn't (e.g., sending `{"is_admin": true}` in a PUT request and the backend blindly saving it).
**Impact:** Unauthorized privilege escalation or exposure of PII/sensitive internal states.

## API4:2023 - Unrestricted Resource Consumption
**The Flaw:** The API does not restrict the amount of resources a client can request. This isn't just about rate limiting (requests per second); it includes execution timeouts, maximum memory allocation, and maximum payload sizes (e.g., allowing a user to upload a 5GB file or request 1,000,000 records in a single pagination query).
**Impact:** Denial of Service (DoS) and massive cloud billing spikes.

## API5:2023 - Broken Function Level Authorization (BFLA)
**The Flaw:** Complex access control policies with different hierarchies and roles are improperly enforced at the endpoint level. For example, an attacker changes the HTTP method from `GET /api/users` to `DELETE /api/users` or navigates to `/api/admin/users`, and the backend fails to verify their role.
**Impact:** Unauthorized execution of administrative functions.

## API6:2023 - Unrestricted Access to Sensitive Business Flows
**The Flaw:** The API exposes a business flow (like buying a ticket, posting a comment, or transferring money) without protections against automated abuse (bots). 
**Impact:** Ticket scalping, comment spam, or automated fraudulent transactions.

## API7:2023 - Server Side Request Forgery (SSRF)
**The Flaw:** The API takes a URL/URI provided by the user and fetches it without validation. 
**Impact:** An attacker can force the server to connect to internal, non-public systems (like `http://169.254.169.254` to steal AWS metadata credentials) or scan the internal network behind the firewall.

## API8:2023 - Security Misconfiguration
**The Flaw:** Insecure default settings, incomplete configurations, open cloud storage, misconfigured HTTP headers, unnecessary HTTP methods, permissive Cross-Origin Resource Sharing (CORS), or verbose error messages containing stack traces.
**Impact:** Exposes the system to a wide variety of attacks and data leaks.

## API9:2023 - Improper Inventory Management
**The Flaw:** Deploying APIs without proper documentation (like Swagger/OpenAPI), leaving old, unpatched API versions running (e.g., `v1` is still active when `v3` is the standard), or exposing staging/testing APIs to the public internet.
**Impact:** Shadow APIs become easy targets because they lack the security controls of the primary production endpoints.

## API10:2023 - Unsafe Consumption of APIs
**The Flaw:** Developers tend to blindly trust data returned from *other* third-party APIs (e.g., Stripe, Twilio, or internal microservices). If that third-party API is compromised or spoofed, the malicious payload is processed without validation.
**Impact:** XSS, SQLi, or RCE caused by malicious data injected via a trusted third-party integration.
