---
title: "Threat Modeling a Multi-Tenant SaaS Application"
type: tutorial
tags: [Threat Modeling, STRIDE, AppSec, SaaS, Cloud Security]
date: 2024-10
readingTime: 15
---

# Threat Modeling a Multi-Tenant SaaS Application

## Introduction

Threat modeling is one of the most effective — and most underused — security practices in modern software development. While many teams rely on penetration testing or vulnerability scanning, these approaches often occur **too late** in the lifecycle and focus on symptoms rather than root causes.

This write-up documents a **practical, step-by-step threat modeling exercise** using the STRIDE methodology, applied to a **multi-tenant SaaS CRM application**. The objective is to demonstrate how threat modeling can be used to identify design-level security risks early and drive meaningful architectural decisions.

The emphasis is on realism, not academic theory.

---

## Why Threat Modeling Matters for SaaS

Multi-tenant SaaS platforms introduce unique security challenges:

- Multiple customers share the same infrastructure
- Authorization failures can lead to cross-tenant data exposure
- Identity becomes the primary security boundary
- Small logic flaws can have large blast radii

Threat modeling helps answer a critical question:

> *“What can go wrong in this system, and how do we prevent it?”*

---

## Target System Overview

### Application Description

The system being modeled is a multi-tenant CRM-style SaaS application with the following characteristics:

- Web frontend (SPA)
- REST API backend
- Central authentication provider
- Shared database with tenant isolation at the application layer
- Cloud-hosted infrastructure

### High-Level Components

- Client (browser)
- API Gateway
- Application Backend
- Authentication / Identity Provider
- Database
- Logging and Monitoring services

---

## Step 1: Identify Trust Boundaries

Trust boundaries represent points where data crosses from one level of trust to another.

### Key Trust Boundaries Identified

- Browser → API
- API → Identity Provider
- Application → Database
- Application → Logging / Monitoring
- Admin users → Management endpoints

Each trust boundary represents an opportunity for abuse if not properly secured.

---

## Step 2: Data Flow Analysis

Understanding how data moves through the system is essential before applying STRIDE.

### Example Data Flows

1. User authenticates via identity provider
2. Access token is issued to the client
3. Client calls API with token
4. API validates token and tenant context
5. API queries database using tenant-scoped filters
6. Response returned to client

Any missing validation or assumption in these steps creates risk.

---

## Step 3: Applying STRIDE

STRIDE categorizes threats into six classes:

- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

Each category was evaluated at every trust boundary.

---

## Spoofing Threats

### Example Threat

An attacker steals or reuses a valid access token to impersonate another user or tenant.

### Root Causes

- Weak token protection
- Long-lived tokens
- Missing audience or tenant validation

### Mitigations

- Short-lived access tokens
- Token audience and issuer validation
- Enforce MFA for privileged users
- Monitor anomalous authentication behavior

---

## Tampering Threats

### Example Threat

A user manipulates API request payloads to modify resources belonging to another tenant.

### Root Causes

- Client-controlled identifiers
- Missing server-side validation
- Over-trusting frontend logic

### Mitigations

- Server-side enforcement of tenant context
- Never trust client-provided tenant IDs
- Use domain-level authorization checks
- Validate all inputs explicitly

---

## Repudiation Threats

### Example Threat

A malicious user performs an action and later denies responsibility.

### Root Causes

- Insufficient audit logging
- Missing user identity context in logs

### Mitigations

- Centralized, immutable audit logs
- Include user ID, tenant ID, timestamp, and action
- Protect logs from tampering
- Retain logs according to policy

---

## Information Disclosure Threats

### Example Threat

Cross-tenant data leakage due to authorization or filtering failures.

### Root Causes

- Missing authorization checks
- Shared database tables without strict filters
- Overly verbose API responses

### Mitigations

- Enforce tenant isolation at the application layer
- Use DTOs to control response data
- Implement automated tests for authorization
- Monitor for anomalous access patterns

---

## Denial of Service Threats

### Example Threat

An attacker overwhelms the API with expensive requests, impacting availability for all tenants.

### Root Causes

- No rate limiting
- Unbounded queries
- Resource-intensive endpoints

### Mitigations

- Global and per-tenant rate limiting
- Request size limits
- Query optimization and pagination
- Autoscaling with cost controls

---

## Elevation of Privilege Threats

### Example Threat

A normal user gains administrative capabilities by exploiting missing authorization checks.

### Root Causes

- Role checks implemented inconsistently
- Shared endpoints for admin and non-admin actions
- Overly permissive default roles

### Mitigations

- Explicit role-based access control (RBAC)
- Separate admin APIs from user APIs
- Just-in-time privileged access
- Regular access reviews

---

## Step 4: Risk Prioritization

Not all threats are equal. Risks were prioritized based on:

- Likelihood of exploitation
- Impact on confidentiality, integrity, and availability
- Blast radius in a multi-tenant environment

### Highest Priority Risks

1. Broken object-level authorization
2. Cross-tenant data exposure
3. Privilege escalation
4. Token misuse

---

## Step 5: Mapping Threats to Controls

Threat modeling is only valuable if it drives action.

Key outcomes:
- Security requirements added to design docs
- Authorization logic centralized in the domain layer
- Logging requirements defined early
- Abuse cases included in test plans

---

## Common Mistakes Observed

- Treating threat modeling as a one-time activity
- Performing it after implementation
- Ignoring business logic abuse
- Focusing only on infrastructure threats

Threat modeling is most effective **before code is written**.

---

## Key Lessons Learned

- Multi-tenancy dramatically increases security risk
- Identity and authorization are the primary attack surfaces
- Threat modeling improves architecture, not just security
- STRIDE provides structure without being restrictive

---

## Conclusion

Threat modeling transforms security from a reactive practice into a proactive design discipline. By applying STRIDE early and systematically, it becomes possible to identify critical risks before they are embedded into code and infrastructure.

This exercise reinforced the importance of designing security boundaries explicitly and treating authorization as a first-class architectural concern — especially in multi-tenant SaaS environments.

---

## References

- Microsoft STRIDE Threat Modeling
- OWASP Application Threat Modeling
- NIST Secure Software Development Framework (SSDF)
