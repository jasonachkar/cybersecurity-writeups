# API and Microservices Threat Modeling

> Status: OUTLINE DRAFT – to be expanded with full research

## Executive Summary

This document presents a practical threat modeling approach for APIs and microservices in cloud-native applications. It focuses on data flow modeling, trust boundaries, common vulnerability classes (e.g., broken authn/authz, injection, IDOR), and layered mitigations using gateways, identity systems, and runtime defenses.

## 1. API-Centric Threat Modeling in Microservices

- Why API-centric threat modeling is necessary in distributed systems.
- Using data flow diagrams and STRIDE-like techniques adapted to microservices.

## 2. Trust Boundaries and Attack Surfaces

- External clients, gateways, internal services, data stores, and third-party integrations.
- Identifying trust boundaries and attack surfaces across API calls.

## 3. Common Vulnerabilities and Abuse Patterns

- Broken authentication and authorization, IDOR, and injection attacks.
- Rate limiting, resource exhaustion, and abuse of APIs.

## 4. Layered Mitigation Strategies

- Strong authn/authz at gateways and services.
- Input validation, schema enforcement, and safe serialization.
- Protection of service-to-service communication, rate limiting, and API gateways as policy enforcement points.

## 5. Threat Modeling as a Continuous Practice

- Integrating threat modeling into development and operations workflows.
- Using automated checks and observability to maintain threat models over time.

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
