# Threat Modeling Mitigations for SaaS

Once threats are identified via STRIDE and mapped on Data Flow Diagrams, they must be addressed. Mitigations in a SaaS environment heavily focus on enforcing tenant boundaries, securing APIs, and ensuring robust auditing.

---

## 1. Mitigating Spoofing (Identity Protection)

* **Implement Robust Authentication:** Enforce Multi-Factor Authentication (MFA) for all tenant users and administrators.
* **Secure Session Management:** Use secure, HttpOnly, and SameSite flags for cookies. If using JWTs, ensure they are signed with strong algorithms (e.g., RS256) and that the signing keys are rotated regularly via a KMS (Key Management Service).
* **Context-Aware Access:** Evaluate the risk of the login attempt (e.g., unexpected geolocation, impossible travel, unknown device) before granting access.

## 2. Mitigating Tampering (Integrity Protection)

* **Encryption in Transit:** Enforce TLS 1.2 or 1.3 for all communications, both external (Client $\rightarrow$ ALB) and internal (Microservice $\rightarrow$ Microservice).
* **Input Validation:** Validate all input on the server side using strict allow-lists. Never trust client-provided data, especially identifiers like `tenant_id` or `role`.
* **Database Security:** Use parameterized queries or Object-Relational Mappers (ORMs) to entirely eliminate the risk of SQL Injection.

## 3. Mitigating Repudiation (Non-Repudiation / Auditing)

* **Comprehensive Audit Trails:** Log all critical actions (authentication events, authorization failures, data mutations, administrative changes).
* **Immutable Storage:** Send audit logs to a centralized, write-once-read-many (WORM) storage bucket (like AWS S3 Object Lock) where even system administrators cannot alter or delete them.
* **Contextual Logging:** Ensure every log entry contains the `tenant_id`, `user_id`, `timestamp`, `source_ip`, and the `action_performed` to reconstruct exactly what happened.

## 4. Mitigating Information Disclosure (Confidentiality)

* **Enforce Tenant Isolation at the Database Level:**
    * *Pool Model (Shared DB):* Enforce Row-Level Security (RLS) in databases like PostgreSQL to ensure queries automatically filter by the current tenant context.
    * *Silo Model (Dedicated DB):* Provision separate databases or schemas per tenant to physically or logically separate data.
* **Strict Access Controls (BOLA Prevention):** Implement mandatory authorization checks on every API endpoint to verify the user actually owns the specific resource (e.g., verifying `invoice.tenant_id == current_user.tenant_id`).
* **Secrets Management:** Never hardcode API keys or database credentials. Use dynamic secrets injected at runtime via HashiCorp Vault or AWS Secrets Manager.

## 5. Mitigating Denial of Service (Availability)

* **Rate Limiting & Throttling:** Implement rate limiting at the API Gateway based on the `tenant_id` or IP address to prevent "Noisy Neighbors" from exhausting shared resources.
* **Infrastructure Auto-Scaling:** Design stateless applications that can automatically scale out horizontally under heavy load.
* **Edge Protection:** Deploy a Cloud Web Application Firewall (WAF) and DDoS protection services (e.g., Cloudflare, AWS Shield) to absorb volumetric attacks before they hit the application servers.

## 6. Mitigating Elevation of Privilege (Authorization)

* **Principle of Least Privilege:** Services and users should operate with the bare minimum permissions necessary. (e.g., The web server shouldn't have `DROP TABLE` permissions).
* **Role-Based Access Control (RBAC):** Implement strict, well-defined roles. Ensure that authorization decisions are made on the server side based on trusted backend data, not on claims easily manipulated by the client.
* **Continuous Authorization:** Re-validate user permissions continuously, especially for sensitive actions, rather than just at login time.
