# OWASP API Security Top 10: Practical Mitigations

## Introduction

APIs are the backbone of modern applications — and one of the most frequently attacked surfaces. Unlike traditional web vulnerabilities, API security failures are often **logic flaws**, not missing patches or misconfigured servers.

This write-up provides a **practical, engineering-focused analysis** of the OWASP API Security Top 10. Rather than restating definitions, the focus is on:

- How these vulnerabilities actually appear in production systems  
- Why they are frequently missed during development  
- Concrete mitigation strategies for **Node.js** and **.NET** backends  

The goal is to bridge the gap between security theory and real-world API development.

---

## API1: Broken Object Level Authorization (BOLA)

### Description

BOLA occurs when APIs expose object identifiers (IDs) and fail to verify whether the authenticated user is authorized to access the requested object.

This is the **most common and most dangerous** API vulnerability.

### Real-World Example

```http
GET /api/orders/12345
````

If the API only checks authentication but not ownership, an attacker can iterate IDs and access other users’ data.

### Why It Happens

* Developers assume authentication implies authorization
* Authorization logic is implemented inconsistently
* Object ownership checks are missing or incomplete

### Mitigation Strategies

* Perform authorization checks **on every object access**
* Never trust client-supplied identifiers
* Enforce ownership checks at the service or domain layer
* Prefer opaque identifiers where possible

**.NET Example**

* Use policy-based authorization
* Validate ownership inside application services, not controllers

**Node.js Example**

* Centralize authorization middleware
* Never rely on frontend filtering

---

## API2: Broken Authentication

### Description

Broken authentication occurs when APIs improperly implement authentication mechanisms, leading to account takeover or session abuse.

### Common Issues

* Weak or missing MFA
* Long-lived access tokens
* Tokens stored insecurely
* Improper token revocation

### Why It Happens

* Convenience-driven design decisions
* Poor understanding of OAuth flows
* Treating tokens as non-sensitive data

### Mitigation Strategies

* Use short-lived access tokens
* Implement refresh token rotation
* Enforce MFA for sensitive operations
* Secure token storage (never in local storage)

---

## API3: Broken Object Property Level Authorization (BOPLA)

### Description

BOPLA occurs when APIs expose or allow modification of object properties that users should not see or change.

### Example

```json
{
  "email": "user@example.com",
  "role": "admin"
}
```

If the API accepts this payload without validation, privilege escalation becomes trivial.

### Mitigation Strategies

* Use explicit DTOs for requests and responses
* Never bind domain models directly to request bodies
* Validate both **read** and **write** access to properties

---

## API4: Unrestricted Resource Consumption

### Description

APIs that fail to enforce limits can be abused for denial-of-service or cost exhaustion attacks.

### Examples

* No rate limiting
* Large payload uploads
* Unbounded pagination
* Expensive queries without limits

### Mitigation Strategies

* Implement global and per-user rate limits
* Enforce request size limits
* Apply pagination with hard maximums
* Monitor abnormal usage patterns

---

## API5: Broken Function Level Authorization (BFLA)

### Description

BFLA occurs when APIs fail to restrict access to administrative or sensitive endpoints.

### Example

```http
POST /api/admin/users
```

Accessible to non-admin users due to missing role checks.

### Mitigation Strategies

* Enforce role-based access control (RBAC)
* Use explicit authorization attributes or middleware
* Test authorization logic separately from business logic

---

## API6: Unrestricted Access to Sensitive Business Flows

### Description

Some API endpoints represent **business-critical actions**, such as password resets, refunds, or account changes.

### Risks

* Abuse of password reset endpoints
* Automated account enumeration
* Financial or operational impact

### Mitigation Strategies

* Add rate limits to sensitive workflows
* Require additional verification for critical actions
* Monitor and alert on abuse patterns

---

## API7: Server-Side Request Forgery (SSRF)

### Description

SSRF occurs when APIs fetch external resources based on user input without validation.

### Example

```json
{
  "url": "http://169.254.169.254/latest/meta-data/"
}
```

### Mitigation Strategies

* Validate and whitelist outbound destinations
* Block access to internal IP ranges
* Avoid dynamic URL fetching when possible

---

## API8: Security Misconfiguration

### Description

Security misconfiguration includes overly permissive CORS, debug endpoints, verbose errors, and default credentials.

### Mitigation Strategies

* Disable debug and admin endpoints in production
* Use secure CORS configurations
* Standardize environment hardening
* Treat configuration as code

---

## API9: Improper Inventory Management

### Description

APIs often expose undocumented or deprecated endpoints that are still accessible.

### Risks

* Shadow APIs
* Forgotten admin endpoints
* Inconsistent security controls

### Mitigation Strategies

* Maintain an up-to-date API inventory
* Remove unused endpoints
* Enforce authentication consistently
* Version APIs explicitly

---

## API10: Unsafe Consumption of APIs

### Description

This vulnerability applies when your API consumes **other APIs** insecurely.

### Examples

* Trusting third-party API responses blindly
* Failing to validate schemas
* Not handling upstream failures securely

### Mitigation Strategies

* Validate all third-party responses
* Apply timeouts and circuit breakers
* Treat external APIs as untrusted input

---

## Key Takeaways

* Authentication without authorization is meaningless
* APIs fail due to logic errors, not missing patches
* Secure defaults matter more than complex controls
* Authorization must be explicit and centralized

---

## Conclusion

API security is fundamentally about **trust boundaries**. Every request, identifier, and payload must be treated as untrusted input. By designing APIs with explicit authorization, strict validation, and enforced limits, entire classes of vulnerabilities can be eliminated.

This research significantly influenced how I design and review APIs, particularly in multi-tenant and cloud-native environments.

---

## References

* OWASP API Security Top 10
* NIST SP 800-53
* OAuth 2.0 Threat Model

