# API and Microservices Threat Modeling

> Status: IN PROGRESS – deep-dive draft

## Executive Summary

In cloud-native systems, APIs are the primary interface through which users, services, and third parties interact with your application. In a microservices architecture, each service often exposes its own API, multiplying the number of places where attackers can interact with your system. This document presents a practical, API-centric threat modeling approach that senior engineers can use to understand and mitigate risks across distributed services. It focuses on data flows, trust boundaries, common vulnerability classes, and layered mitigations using gateways, identity systems, and runtime controls.[web:128][web:130][web:135]

## 1. API-Centric Threat Modeling in Microservices

### 1.1 Why API-Centric Threat Modeling Matters

Traditional threat modeling approaches often assume a single monolithic application with a clear perimeter. Microservices architectures, by contrast, distribute functionality across many services and APIs:[web:130][web:135]

- Each service may have its own endpoints and data stores.
- Services communicate via APIs using HTTP, gRPC, or messaging.
- Third-party integrations and internal services expand the attack surface.

API-centric threat modeling focuses on how data moves between clients, gateways, services, and stores, and how attackers might abuse those flows.

### 1.2 Data Flow Diagrams and STRIDE-like Techniques

A practical starting point is to draw data flow diagrams (DFDs):[web:128][web:130]

- Identify entities: external clients, identity providers, API gateways, microservices, databases, caches, and message queues.
- Draw data flows: request/response paths, background jobs, events, and callbacks.
- Mark trust boundaries: points where data crosses from one trust domain to another (e.g., Internet → gateway, gateway → internal service, service → data store).

With DFDs in place, you can apply STRIDE-like analysis (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) to each data flow and boundary, focusing on API-specific concerns.

## 2. Trust Boundaries and Attack Surfaces

### 2.1 Key Trust Boundaries

Important boundaries in microservices architectures include:[web:128][web:130]

- Internet → API gateway or edge services.
- Gateway → internal services.
- Services → data stores and external APIs.

At each boundary, consider:

- Who is allowed to send requests and with what credentials.
- What assumptions services make about identity and authorization.
- How data is validated, transformed, and logged.

### 2.2 Attack Surfaces Across API Calls

Attackers can target:

- Public API endpoints exposed to the Internet.
- Internal APIs exposed to other services or to private clients.
- Administrative and operational APIs used by tools and operators.[web:130][web:135]

Threat modeling helps identify which APIs are most sensitive and require stronger controls.

## 3. Common Vulnerabilities and Abuse Patterns

### 3.1 Broken Authentication and Authorization

Common authn/authz issues in API-based microservices include:[web:130][web:135]

- Missing or inconsistent enforcement of authentication across endpoints.
- Authorization checks performed only at the gateway, with internal services assuming all requests are trusted.
- Insecure multi-tenant authorization, where tenant identifiers are not properly validated or enforced.

Threat modeling should ask:

- Where is authentication enforced?
- Where and how are authorization decisions made?
- How do services know which tenant and user a request belongs to?

### 3.2 IDOR and Injection Attacks

Insecure direct object references (IDOR) and injection attacks are prevalent in APIs:[web:130][web:135]

- IDOR arises when APIs expose resource identifiers without ensuring that callers are authorized to access those resources.
- Injection occurs when user-controlled data is passed to interpreters (SQL, NoSQL, command shells, template engines) without proper sanitization.

Threat modeling should consider:

- How APIs validate identifiers and enforce ownership.
- Where data enters the system and how it is validated before reaching interpreters.

### 3.3 Rate Limiting, Resource Exhaustion, and Abuse

APIs can be abused to exhaust resources:

- Attackers may send high volumes of requests to critical endpoints.
- Misuse of expensive operations (e.g., search, report generation) can impact availability.[web:130]

Threat models should include abuse scenarios and consider rate limiting and throttling strategies.

## 4. Layered Mitigation Strategies

### 4.1 Strong Authn/Authz at Gateways and Services

Gateways and services should work together:

- Gateways enforce authentication and coarse-grained authorization (e.g., scopes, roles, tenant membership).
- Services perform fine-grained authorization based on resource ownership and business rules.[web:130][web:135]

Threat modeling should ensure that authorization is not assumed, but explicitly checked at appropriate layers.

### 4.2 Input Validation, Schemas, and Safe Serialization

Robust input validation mitigates many issues:[web:130]

- Use schemas (e.g., OpenAPI/JSON Schema) to define expected inputs.
- Enforce schema validation at gateways or service boundaries.
- Avoid passing unvalidated data directly to interpreters.

Threat modeling helps identify which inputs require stricter validation.

### 4.3 Protecting Service-to-Service Communication

Service-to-service calls should be protected:[web:128][web:130]

- Use mutual TLS and identity-aware routing where appropriate.
- Ensure that internal APIs still enforce authorization, not just trust the gateway.

This reduces the impact of compromised internal services or misconfigured gateways.

### 4.4 Rate Limiting and API Gateways as Policy Enforcement Points

Gateways can enforce policies beyond routing:[web:130][web:135]

- Apply rate limits and quotas per client, user, or tenant.
- Block or throttle abusive patterns.

Threat modeling should identify which endpoints and clients need additional protections.

## 5. Threat Modeling as a Continuous Practice

### 5.1 Integrating into Development and Operations

Threat modeling works best when it is continuous:[web:135]

- Incorporate threat modeling into design reviews for new APIs and services.
- Revisit models when significant changes occur (new endpoints, new integrations).

### 5.2 Automated Checks and Observability

Automation and observability help maintain threat models:

- Use API gateways and observability tools to detect unusual traffic patterns.
- Integrate security tests and scanners into CI/CD pipelines.

Threat models should inform what to monitor and what automated checks to implement.

---

# Advanced OAuth 2.0 / OIDC Security in SaaS

> Status: OUTLINE DRAFT – to be expanded with full research

## Executive Summary

This document covers modern OAuth 2.0 and OpenID Connect (OIDC) security practices for SaaS applications. It focuses on secure flows (Authorization Code + PKCE), token handling, scopes, multi-tenant patterns, and defenses against common attacks.

## 1. Protocol Components and Flows

- Overview of OAuth 2.0 grant types and OIDC tokens.
- Modern best practices (deprecation of implicit and resource owner flows, use of PKCE).

## 2. Attack Surface and Vulnerabilities

- Authorization code interception, redirect URI issues, token leakage.
- Misconfigured scopes and consent, multi-tenant token misuse.

## 3. Secure Flow Design and Token Handling

- Designing flows with PKCE, secure redirect URIs, and proper token lifetimes.
- Storage and validation of ID and access tokens in web and mobile clients.

## 4. Multi-Tenant Authn/Authz Patterns

- Tenant-aware identity and scopes.
- Role and attribute-based access for SaaS customers.

## 5. Operational Practices and Hardening

- Monitoring OAuth/OIDC events and anomalies.
- Rotating keys and managing client registrations.

---

# SaaS Multitenancy and Data Isolation

> Status: OUTLINE DRAFT – to be expanded with full research

## Executive Summary

This document describes multi-tenant SaaS isolation strategies across data, application, infrastructure, and identity layers. It aims to help senior engineers design systems that prevent tenant A from accessing tenant B's data or resources, while balancing cost and operational complexity.

## 1. Tenancy Models and Mental Model

- Understanding tenants as units of data ownership and configuration.
- Isolation models (silo, pool, bridge) and their trade-offs.

## 2. Data Isolation Patterns

- Database-per-tenant, schema-per-tenant, and row-level security.
- Cryptographic isolation and key management.

## 3. Application and API Isolation

- Request-path tenant context and enforcement.
- Avoiding cross-tenant vulnerabilities (IDOR, confused deputy, shared caching issues).

## 4. Infrastructure and Identity Isolation

- Mapping tenants to infrastructure (accounts, projects, namespaces) and identity systems.
- Tenant-scoped authentication, API key management, and SSO patterns.

## 5. Testing and Validating Isolation

- Approaches to testing tenant isolation guarantees.
- Continuous validation and monitoring for cross-tenant issues.
