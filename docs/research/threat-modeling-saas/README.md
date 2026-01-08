# Threat Modeling for Multi-Tenant SaaS Applications

A comprehensive guide to identifying, analyzing, and mitigating security threats in multi-tenant Software-as-a-Service architectures using STRIDE and other methodologies.

## Table of Contents

1. [Introduction](#introduction)
2. [Multi-Tenant Architecture Patterns](#multi-tenant-architecture-patterns)
3. [The STRIDE Framework](#the-stride-framework)
4. [Trust Boundaries in SaaS](#trust-boundaries-in-saas)
5. [Tenant Isolation Threats](#tenant-isolation-threats)
6. [Data Flow Diagrams](#data-flow-diagrams)
7. [Threat Catalog](#threat-catalog)
8. [Mitigation Strategies](#mitigation-strategies)
9. [Threat Modeling Process](#threat-modeling-process)
10. [Case Study: B2B SaaS Platform](#case-study-b2b-saas-platform)

---

## Introduction

### What is Threat Modeling?

Threat modeling is a structured approach to identifying security threats, understanding their potential impact, and designing countermeasures. For multi-tenant SaaS applications, this process is critical because:

- **Shared infrastructure** creates cross-tenant attack vectors
- **Data co-location** increases breach impact
- **Complex trust boundaries** exist between tenants, users, and services
- **Compliance requirements** (GDPR, HIPAA, SOC 2) demand documented security controls

### Why Multi-Tenant SaaS is Different

```
Traditional Application              Multi-Tenant SaaS
┌─────────────────────┐              ┌─────────────────────────────────┐
│   Single Customer   │              │  Tenant A  │  Tenant B  │  ...  │
│   Single Database   │              ├────────────┴────────────┴───────┤
│   Isolated Infra    │              │      Shared Application Layer   │
└─────────────────────┘              │      Shared Infrastructure      │
                                     │      Shared Database (maybe)    │
                                     └─────────────────────────────────┘
```

**Key Differences:**
- Single vulnerability can expose ALL tenant data
- Noisy neighbor performance impacts
- Cross-tenant escalation paths
- Shared secrets and credentials
- Complex authorization models

### State of Threat Modeling (2024-2025)

According to recent industry surveys:
- **88%** of organizations use STRIDE as part of their threat modeling strategy
- **37%** cite diagrams as the primary source for identifying threats
- Cloud-native architectures require adaptation of traditional methodologies
- Continuous threat modeling is becoming integrated into CI/CD pipelines

---

## Multi-Tenant Architecture Patterns

### Isolation Models

| Model | Description | Isolation Level | Cost | Complexity |
|-------|-------------|-----------------|------|------------|
| **Silo (Database per Tenant)** | Dedicated database per tenant | Highest | Highest | Medium |
| **Bridge (Schema per Tenant)** | Shared database, separate schemas | High | Medium | Medium |
| **Pool (Row-Level Security)** | Shared database/tables, tenant_id column | Lowest | Lowest | Highest |
| **Hybrid** | Mix based on tenant tier | Variable | Variable | Highest |

### Silo Model (Database per Tenant)

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  Tenant A   │  │  Tenant B   │  │  Tenant C   │          │
│  │  Database   │  │  Database   │  │  Database   │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

**Security Characteristics:**
- ✅ Strongest data isolation
- ✅ Tenant-specific encryption keys possible
- ✅ Independent backup/restore
- ❌ Connection string management complexity
- ❌ Highest infrastructure cost

### Pool Model (Shared Everything)

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Shared Database                         │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │ tenant_id │ data_column_1 │ data_column_2   │    │    │
│  │  ├───────────┼───────────────┼─────────────────┤    │    │
│  │  │ tenant_a  │ ...           │ ...             │    │    │
│  │  │ tenant_b  │ ...           │ ...             │    │    │
│  │  │ tenant_c  │ ...           │ ...             │    │    │
│  │  └─────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

**Security Characteristics:**
- ✅ Cost-effective
- ✅ Simplified management
- ❌ Application must enforce isolation
- ❌ Single point of compromise
- ❌ Query errors can leak data

### Hybrid Model

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│              (Tenant Routing Logic)                          │
├──────────────────────┬──────────────────────────────────────┤
│   Enterprise Tier    │         Standard Tier                 │
│  ┌────────────────┐  │  ┌────────────────────────────────┐  │
│  │ Dedicated DB   │  │  │     Shared Database            │  │
│  │ (per tenant)   │  │  │  (Row-Level Security)          │  │
│  └────────────────┘  │  └────────────────────────────────┘  │
└──────────────────────┴──────────────────────────────────────┘
```

**Security Characteristics:**
- ✅ Flexibility for different security requirements
- ✅ Cost optimization
- ❌ Complex routing logic
- ❌ Migration paths between tiers

---

## The STRIDE Framework

STRIDE is a threat classification model developed by Microsoft that categorizes threats into six categories, each representing a violation of a security property.

### STRIDE Categories

| Category | Violated Property | Description | Example in SaaS |
|----------|-------------------|-------------|-----------------|
| **S**poofing | Authentication | Impersonating a user or system | Forged JWT tokens, session hijacking |
| **T**ampering | Integrity | Unauthorized data modification | Modifying tenant data via API |
| **R**epudiation | Non-repudiation | Denying actions without proof | Missing audit logs for admin actions |
| **I**nformation Disclosure | Confidentiality | Exposing data to unauthorized parties | Cross-tenant data leakage |
| **D**enial of Service | Availability | Disrupting service availability | Noisy neighbor exhausting resources |
| **E**levation of Privilege | Authorization | Gaining unauthorized access | Tenant user accessing admin functions |

### STRIDE Applied to Multi-Tenant SaaS

```
┌─────────────────────────────────────────────────────────────────────┐
│                        STRIDE Threat Map                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SPOOFING                          TAMPERING                         │
│  ├─ Tenant impersonation           ├─ Data modification via IDOR    │
│  ├─ Token forgery                  ├─ Mass assignment attacks       │
│  ├─ API key theft                  ├─ SQL injection                 │
│  └─ Session fixation               └─ Parameter manipulation        │
│                                                                      │
│  REPUDIATION                       INFORMATION DISCLOSURE            │
│  ├─ Missing audit trails           ├─ Cross-tenant data access      │
│  ├─ Log tampering                  ├─ Error message leakage         │
│  ├─ Insufficient logging           ├─ Insecure API responses        │
│  └─ Time manipulation              └─ Backup exposure               │
│                                                                      │
│  DENIAL OF SERVICE                 ELEVATION OF PRIVILEGE            │
│  ├─ Resource exhaustion            ├─ Horizontal privilege escalation│
│  ├─ Noisy neighbor                 ├─ Vertical privilege escalation │
│  ├─ API rate limit bypass          ├─ Role manipulation             │
│  └─ Storage quota attacks          └─ Tenant admin takeover         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Trust Boundaries in SaaS

Trust boundaries define where data or execution crosses from one trust level to another. These are critical points requiring security controls.

### Typical SaaS Trust Boundaries

```
                    INTERNET (Untrusted)
                           │
    ═══════════════════════╪═══════════════════════  Trust Boundary 1
                           │                          (External/Internal)
                    ┌──────▼──────┐
                    │   WAF/CDN   │
                    └──────┬──────┘
                           │
    ═══════════════════════╪═══════════════════════  Trust Boundary 2
                           │                          (Public/Private)
                    ┌──────▼──────┐
                    │ API Gateway │
                    │ (AuthN/AuthZ)│
                    └──────┬──────┘
                           │
    ═══════════════════════╪═══════════════════════  Trust Boundary 3
                           │                          (User/Tenant Context)
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌───▼───┐ ┌──────▼──────┐
       │ Web Service │ │ API   │ │ Background  │
       │             │ │Service│ │   Worker    │
       └──────┬──────┘ └───┬───┘ └──────┬──────┘
              │            │            │
    ═══════════╪════════════╪════════════╪═════════  Trust Boundary 4
              │            │            │            (App/Data)
              └────────────┼────────────┘
                           │
                    ┌──────▼──────┐
                    │  Database   │
                    │ (RLS/Schema)│
                    └─────────────┘
```

### Trust Boundary Analysis Questions

| Boundary | Questions to Ask |
|----------|------------------|
| External → Internal | Is TLS enforced? Are DDoS protections in place? |
| Public → Private | Is authentication required? Is the token validated? |
| User → Tenant | Is tenant context set correctly? Can users access other tenants? |
| App → Data | Is RLS enforced? Are queries parameterized? |
| Tenant → Tenant | Can Tenant A access Tenant B's data? Resources? |
| Service → Service | Is service-to-service auth implemented? Are secrets rotated? |

---

## Tenant Isolation Threats

### Cross-Tenant Attack Vectors

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Cross-Tenant Attack Surface                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  APPLICATION LAYER                                                   │
│  ├─ IDOR (Insecure Direct Object Reference)                         │
│  │   └─ GET /api/invoices/{invoice_id}  ← No tenant check          │
│  ├─ Broken Object-Level Authorization (BOLA)                        │
│  │   └─ API accepts any tenant's resource ID                        │
│  ├─ Mass Assignment                                                  │
│  │   └─ POST /api/users with tenant_id in body                      │
│  └─ GraphQL Over-fetching                                            │
│      └─ Query returns data from multiple tenants                    │
│                                                                      │
│  DATA LAYER                                                          │
│  ├─ Missing Row-Level Security                                       │
│  │   └─ SELECT * without tenant_id filter                           │
│  ├─ Search Index Leakage                                             │
│  │   └─ Elasticsearch returns cross-tenant results                  │
│  ├─ Cache Poisoning                                                  │
│  │   └─ Tenant A's data cached and served to Tenant B               │
│  └─ Backup/Export Leakage                                            │
│      └─ Export function includes other tenants' data                │
│                                                                      │
│  INFRASTRUCTURE LAYER                                                │
│  ├─ Shared Storage Buckets                                           │
│  │   └─ S3 paths predictable across tenants                         │
│  ├─ Shared Queues                                                    │
│  │   └─ Message from Tenant A processed by Tenant B's worker        │
│  ├─ Log Aggregation                                                  │
│  │   └─ Logs contain cross-tenant sensitive data                    │
│  └─ Container Escape                                                 │
│      └─ Shared Kubernetes cluster, namespace breakout               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### IDOR in Multi-Tenant Context

**Vulnerable Pattern:**
```http
GET /api/tenants/tenant-a/documents/doc-123
Authorization: Bearer <token_for_tenant_b_user>
```

If the application only validates the token but doesn't verify that `tenant-a` matches the token's tenant claim, **cross-tenant access occurs**.

**Attack Scenarios:**

| Attack Type | Description | Impact |
|-------------|-------------|--------|
| Sequential ID Enumeration | Increment document IDs to find others | Data exposure |
| UUID Prediction | Guess or brute-force UUIDs | Targeted access |
| Path Traversal | Manipulate tenant slug in URL | Complete tenant takeover |
| Header Injection | Override tenant context via headers | Bypass isolation |

---

## Data Flow Diagrams

### Creating DFDs for Threat Modeling

Data Flow Diagrams (DFDs) are visual representations of how data moves through a system. They're essential for threat modeling because they help identify trust boundaries and potential attack surfaces.

### DFD Elements

| Element | Symbol | Description |
|---------|--------|-------------|
| External Entity | Rectangle | Users, external systems |
| Process | Circle | Application logic |
| Data Store | Parallel lines | Databases, caches |
| Data Flow | Arrow | Data movement |
| Trust Boundary | Dashed line | Security perimeter |

### Example: Multi-Tenant Invoice System

```
                                    TRUST BOUNDARY: Internet
═══════════════════════════════════════════════════════════════════════
                                         │
                        ┌────────────────▼────────────────┐
                        │          Tenant User            │
                        │      (External Entity)          │
                        └────────────────┬────────────────┘
                                         │
                                    [1] HTTPS Request
                                    (Invoice Data)
                                         │
═══════════════════════════════════════════════════════════════════════
                    TRUST BOUNDARY: DMZ / Public Cloud                 
                                         │
                        ┌────────────────▼────────────────┐
                        │         API Gateway             │
                        │    (AuthN, Rate Limiting)       │
                        └────────────────┬────────────────┘
                                         │
                                    [2] Validated Request
                                    (+ Tenant Context)
                                         │
═══════════════════════════════════════════════════════════════════════
                    TRUST BOUNDARY: Application Tier                   
                                         │
                        ┌────────────────▼────────────────┐
                        │       Invoice Service           │
                        │   (Business Logic, AuthZ)       │
                        └───────┬────────────────┬────────┘
                                │                │
                    [3] Query   │                │  [4] Publish Event
                    (with RLS)  │                │
                                │                │
═══════════════════════════════════════════════════════════════════════
                    TRUST BOUNDARY: Data Tier                          
                                │                │
               ┌────────────────▼───┐    ┌───────▼────────────────┐
               │     PostgreSQL     │    │    Message Queue       │
               │   (RLS Policies)   │    │   (Tenant Routing)     │
               │═══════════════════ │    └────────────────────────┘
               │ tenant_id (filter) │
               └────────────────────┘
```

### Threat Identification from DFD

| Data Flow | STRIDE Threats | Questions |
|-----------|----------------|-----------|
| [1] User → Gateway | S, T, D | Is TLS enforced? Can requests be forged? |
| [2] Gateway → Service | S, I, E | Is tenant context validated? Can it be spoofed? |
| [3] Service → Database | T, I, E | Are queries parameterized? Is RLS enforced? |
| [4] Service → Queue | T, R, I | Are messages signed? Can they be intercepted? |

---

## Threat Catalog

### Comprehensive Multi-Tenant SaaS Threats

#### Authentication Threats (Spoofing)

| ID | Threat | Description | STRIDE | Likelihood | Impact |
|----|--------|-------------|--------|------------|--------|
| AUTH-01 | JWT Token Forgery | Attacker creates valid-looking token with different tenant_id | S | Medium | Critical |
| AUTH-02 | Session Fixation | Attacker fixates session to gain tenant access | S | Low | High |
| AUTH-03 | API Key Leakage | Tenant API keys exposed in logs/repos | S | High | Critical |
| AUTH-04 | OAuth Misconfiguration | Redirect URI allows cross-tenant token theft | S | Medium | Critical |
| AUTH-05 | SSO Bypass | SAML/OIDC implementation flaws | S | Low | Critical |

#### Data Access Threats (Information Disclosure)

| ID | Threat | Description | STRIDE | Likelihood | Impact |
|----|--------|-------------|--------|------------|--------|
| DATA-01 | Cross-Tenant IDOR | Direct object reference exposes other tenant data | I | High | Critical |
| DATA-02 | Search Index Leakage | Full-text search returns cross-tenant results | I | Medium | High |
| DATA-03 | Backup Exposure | Tenant data included in wrong backup | I | Low | Critical |
| DATA-04 | Error Message Leakage | Stack traces reveal tenant information | I | High | Medium |
| DATA-05 | Cache Pollution | Cached responses served to wrong tenant | I | Medium | High |
| DATA-06 | Log Data Exposure | Sensitive tenant data logged in plaintext | I | High | High |

#### Authorization Threats (Elevation of Privilege)

| ID | Threat | Description | STRIDE | Likelihood | Impact |
|----|--------|-------------|--------|------------|--------|
| AUTHZ-01 | Horizontal Escalation | User A accesses User B's resources (same tenant) | E | High | High |
| AUTHZ-02 | Vertical Escalation | Regular user gains admin privileges | E | Medium | Critical |
| AUTHZ-03 | Tenant Admin Takeover | User becomes admin of different tenant | E | Low | Critical |
| AUTHZ-04 | Role Manipulation | User modifies their own role claims | E | Medium | High |
| AUTHZ-05 | Missing Function-Level Access | API endpoints lack authorization checks | E | High | High |

#### Availability Threats (Denial of Service)

| ID | Threat | Description | STRIDE | Likelihood | Impact |
|----|--------|-------------|--------|------------|--------|
| DOS-01 | Noisy Neighbor | One tenant consumes excessive resources | D | High | Medium |
| DOS-02 | Rate Limit Bypass | Attacker circumvents API rate limits | D | Medium | High |
| DOS-03 | Storage Exhaustion | Tenant fills shared storage quota | D | Medium | Medium |
| DOS-04 | Connection Pool Exhaustion | Tenant exhausts database connections | D | Medium | High |
| DOS-05 | Background Job Flooding | Malicious jobs consume worker capacity | D | Medium | Medium |

#### Data Integrity Threats (Tampering)

| ID | Threat | Description | STRIDE | Likelihood | Impact |
|----|--------|-------------|--------|------------|--------|
| TAMP-01 | SQL Injection | Attacker modifies data via injection | T | Medium | Critical |
| TAMP-02 | Mass Assignment | Attacker sets protected fields (tenant_id) | T | High | Critical |
| TAMP-03 | CSRF | Attacker tricks user into modifying data | T | Medium | High |
| TAMP-04 | Message Queue Tampering | Attacker injects/modifies queue messages | T | Low | High |
| TAMP-05 | Webhook Spoofing | Attacker sends fake webhooks | T | Medium | High |

---

## Mitigation Strategies

### Defense in Depth for Multi-Tenant SaaS

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Defense in Depth Layers                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  LAYER 1: Perimeter                                                  │
│  ├─ WAF (Web Application Firewall)                                   │
│  ├─ DDoS Protection (CloudFlare, AWS Shield)                        │
│  ├─ API Gateway with Rate Limiting                                  │
│  └─ TLS 1.3 Everywhere                                              │
│                                                                      │
│  LAYER 2: Authentication                                             │
│  ├─ OAuth 2.0 / OpenID Connect                                      │
│  ├─ MFA for Tenant Admins                                           │
│  ├─ Short-lived Tokens (15 min access, 7 day refresh)               │
│  └─ Token Binding to Tenant Context                                 │
│                                                                      │
│  LAYER 3: Authorization                                              │
│  ├─ RBAC + ABAC Hybrid                                              │
│  ├─ Tenant Context Validation on Every Request                      │
│  ├─ Object-Level Authorization (BOLA prevention)                    │
│  └─ Principle of Least Privilege                                    │
│                                                                      │
│  LAYER 4: Data Isolation                                             │
│  ├─ Row-Level Security (RLS) in Database                            │
│  ├─ Tenant-Scoped Encryption Keys                                   │
│  ├─ Separate Storage Buckets/Prefixes                               │
│  └─ Query Interceptors with Tenant Filters                          │
│                                                                      │
│  LAYER 5: Monitoring & Response                                      │
│  ├─ Cross-Tenant Access Alerting                                    │
│  ├─ Anomaly Detection                                               │
│  ├─ Comprehensive Audit Logging                                     │
│  └─ Incident Response Playbooks                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Mitigation by Threat Category

#### Spoofing Mitigations

```
┌─────────────────────────────────────────────────────────────────────┐
│  MITIGATION: Strong Authentication                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. JWT Token Security                                               │
│     ├─ Sign with RS256 (asymmetric) not HS256                       │
│     ├─ Include tenant_id in claims                                  │
│     ├─ Short expiration (15 minutes)                                │
│     ├─ Validate issuer, audience, expiration                        │
│     └─ Implement token revocation                                   │
│                                                                      │
│  2. API Key Management                                               │
│     ├─ Hash keys in database (never store plaintext)                │
│     ├─ Scope keys to specific tenants                               │
│     ├─ Implement key rotation                                       │
│     └─ Rate limit per key                                           │
│                                                                      │
│  3. SSO/Federation                                                   │
│     ├─ Validate SAML signatures                                     │
│     ├─ Check audience restriction                                   │
│     ├─ Validate issuer against tenant config                        │
│     └─ Implement PKCE for OAuth                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

#### Information Disclosure Mitigations

```python
# Example: Row-Level Security Implementation

# 1. Database-Level RLS (PostgreSQL)
"""
-- Enable RLS on table
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;

-- Create policy
CREATE POLICY tenant_isolation ON invoices
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Set tenant context on each connection
SET app.current_tenant = 'tenant-uuid-here';
"""

# 2. Application-Level Query Interceptor
class TenantQueryInterceptor:
    def __init__(self, tenant_context):
        self.tenant_id = tenant_context.tenant_id
    
    def intercept_query(self, query):
        # Automatically append tenant filter
        if not self._has_tenant_filter(query):
            query = query.filter(tenant_id=self.tenant_id)
        return query
    
    def validate_object(self, obj):
        if obj.tenant_id != self.tenant_id:
            raise CrossTenantAccessError(
                f"Attempt to access tenant {obj.tenant_id} "
                f"from context {self.tenant_id}"
            )

# 3. Response Filtering
class TenantAwareSerializer:
    def serialize(self, data, tenant_context):
        # Filter out any cross-tenant data that slipped through
        if isinstance(data, list):
            return [
                item for item in data 
                if item.tenant_id == tenant_context.tenant_id
            ]
        elif hasattr(data, 'tenant_id'):
            if data.tenant_id != tenant_context.tenant_id:
                raise CrossTenantAccessError()
        return data
```

#### Elevation of Privilege Mitigations

```python
# Example: Object-Level Authorization

from functools import wraps

def authorize_object_access(resource_type):
    """
    Decorator to verify user has access to specific object
    """
    def decorator(func):
        @wraps(func)
        def wrapper(request, resource_id, *args, **kwargs):
            # 1. Get current user and tenant context
            user = request.user
            tenant = request.tenant_context
            
            # 2. Fetch resource (with tenant filter)
            resource = get_resource(
                resource_type, 
                resource_id,
                tenant_id=tenant.id  # Critical: Always filter by tenant
            )
            
            if resource is None:
                raise NotFoundError()
            
            # 3. Verify object belongs to correct tenant
            if resource.tenant_id != tenant.id:
                log_security_event(
                    event_type="CROSS_TENANT_ACCESS_ATTEMPT",
                    user=user,
                    target_tenant=resource.tenant_id,
                    resource=resource_id
                )
                raise ForbiddenError()
            
            # 4. Verify user has permission on this object
            if not has_permission(user, resource, "read"):
                raise ForbiddenError()
            
            return func(request, resource, *args, **kwargs)
        return wrapper
    return decorator

# Usage
@authorize_object_access("invoice")
def get_invoice(request, invoice):
    return InvoiceSerializer(invoice).data
```

---

## Threat Modeling Process

### Step-by-Step Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Threat Modeling Workflow                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  STEP 1: DEFINE SCOPE                                                │
│  ├─ Identify system boundaries                                      │
│  ├─ List assets (data, services, infrastructure)                    │
│  ├─ Define tenant tiers and isolation requirements                  │
│  └─ Gather compliance requirements (SOC 2, GDPR, etc.)              │
│                         │                                            │
│                         ▼                                            │
│  STEP 2: CREATE DATA FLOW DIAGRAMS                                   │
│  ├─ Map external entities (users, systems)                          │
│  ├─ Identify processes (services, APIs)                             │
│  ├─ Document data stores (DBs, caches, queues)                      │
│  └─ Draw trust boundaries                                           │
│                         │                                            │
│                         ▼                                            │
│  STEP 3: IDENTIFY THREATS                                            │
│  ├─ Apply STRIDE to each DFD element                                │
│  ├─ Focus on trust boundary crossings                               │
│  ├─ Consider multi-tenant specific threats                          │
│  └─ Use threat catalogs as reference                                │
│                         │                                            │
│                         ▼                                            │
│  STEP 4: ASSESS RISK                                                 │
│  ├─ Rate likelihood (1-5)                                           │
│  ├─ Rate impact (1-5)                                               │
│  ├─ Calculate risk score (L × I)                                    │
│  └─ Prioritize by risk score                                        │
│                         │                                            │
│                         ▼                                            │
│  STEP 5: DESIGN MITIGATIONS                                          │
│  ├─ Select controls for high-risk threats                           │
│  ├─ Map to security requirements                                    │
│  ├─ Document residual risk                                          │
│  └─ Create implementation tickets                                   │
│                         │                                            │
│                         ▼                                            │
│  STEP 6: VALIDATE                                                    │
│  ├─ Review with stakeholders                                        │
│  ├─ Update on architecture changes                                  │
│  ├─ Verify mitigations implemented                                  │
│  └─ Conduct penetration testing                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Risk Assessment Matrix

```
              │ Negligible │   Low    │  Medium  │   High   │ Critical │
              │     (1)    │   (2)    │   (3)    │   (4)    │   (5)    │
──────────────┼────────────┼──────────┼──────────┼──────────┼──────────┤
Almost        │            │          │          │          │          │
Certain (5)   │     5      │    10    │    15    │    20    │    25    │
──────────────┼────────────┼──────────┼──────────┼──────────┼──────────┤
Likely (4)    │     4      │     8    │    12    │    16    │    20    │
──────────────┼────────────┼──────────┼──────────┼──────────┼──────────┤
Possible (3)  │     3      │     6    │     9    │    12    │    15    │
──────────────┼────────────┼──────────┼──────────┼──────────┼──────────┤
Unlikely (2)  │     2      │     4    │     6    │     8    │    10    │
──────────────┼────────────┼──────────┼──────────┼──────────┼──────────┤
Rare (1)      │     1      │     2    │     3    │     4    │     5    │
──────────────┴────────────┴──────────┴──────────┴──────────┴──────────┘

Risk Levels:
  1-4:   Low (Monitor)
  5-9:   Medium (Address in next sprint)
  10-14: High (Address immediately)
  15-25: Critical (Stop and fix now)
```

---

## Case Study: B2B SaaS Platform

### Scenario: Invoice Management SaaS

**Business Context:**
- B2B SaaS platform for invoice management
- 500+ business customers (tenants)
- Handles financial data subject to PCI-DSS
- Multi-tier offering (Free, Pro, Enterprise)

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Invoice SaaS Architecture                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│    Users                      External Systems                       │
│    ┌─────┐                    ┌─────────────────┐                   │
│    │Admin│                    │ Payment Gateway │                   │
│    │User │                    │ (Stripe)        │                   │
│    └──┬──┘                    └────────┬────────┘                   │
│       │                                │                            │
│═══════╪════════════════════════════════╪════════════════════════════│
│       │         Trust Boundary 1       │                            │
│       │                                │                            │
│    ┌──▼──────────────────────────────┐ │                            │
│    │         CloudFlare WAF          │ │                            │
│    └──┬──────────────────────────────┘ │                            │
│       │                                │                            │
│═══════╪════════════════════════════════╪════════════════════════════│
│       │         Trust Boundary 2       │                            │
│       │                                │                            │
│    ┌──▼──────────────────────────────────▼───────────────┐          │
│    │              API Gateway (Kong)                      │          │
│    │         - JWT Validation                             │          │
│    │         - Rate Limiting                              │          │
│    │         - Tenant Context Extraction                  │          │
│    └──┬──────────────────────────────────────────────────┘          │
│       │                                                              │
│═══════╪═════════════════════════════════════════════════════════════│
│       │              Trust Boundary 3                                │
│       │                                                              │
│    ┌──▼─────────────┐  ┌────────────────┐  ┌───────────────┐        │
│    │ Invoice        │  │ User           │  │ Notification  │        │
│    │ Service        │  │ Service        │  │ Service       │        │
│    └──┬─────────────┘  └───────┬────────┘  └───────┬───────┘        │
│       │                        │                    │                │
│═══════╪════════════════════════╪════════════════════╪════════════════│
│       │         Trust Boundary 4                    │                │
│       │                        │                    │                │
│    ┌──▼────────┐     ┌─────────▼──────┐    ┌───────▼───────┐        │
│    │PostgreSQL │     │    Redis       │    │   RabbitMQ    │        │
│    │ (RLS)     │     │   (Cache)      │    │  (Messages)   │        │
│    └───────────┘     └────────────────┘    └───────────────┘        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Threat Analysis

| Component | STRIDE | Threat | Risk | Mitigation |
|-----------|--------|--------|------|------------|
| API Gateway | S | JWT token forgery | High | RS256 signing, short expiry, issuer validation |
| API Gateway | D | Rate limit bypass | Medium | Distributed rate limiting, per-tenant quotas |
| Invoice Service | I | Cross-tenant IDOR | Critical | Object-level authz, tenant context validation |
| Invoice Service | E | Privilege escalation | High | RBAC, principle of least privilege |
| PostgreSQL | I | RLS bypass | Critical | Defense in depth, app-level checks |
| PostgreSQL | T | SQL injection | High | Parameterized queries, input validation |
| Redis | I | Cache poisoning | High | Tenant-prefixed keys, encryption |
| RabbitMQ | T | Message tampering | Medium | Message signing, tenant routing |
| Stripe Webhook | S | Webhook spoofing | High | Signature verification |

### Identified Critical Threats

#### Threat 1: Cross-Tenant Invoice Access (IDOR)

**Description:** User from Tenant A can access invoices belonging to Tenant B by manipulating the invoice ID in the URL.

**Attack Path:**
```
1. Attacker logs in as user in Tenant A
2. Attacker identifies invoice URL pattern: /api/invoices/{id}
3. Attacker enumerates invoice IDs
4. Application returns invoices from other tenants
```

**Mitigation:**
```python
# Before (Vulnerable)
@app.get("/api/invoices/{invoice_id}")
def get_invoice(invoice_id: str, user: User):
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    return invoice

# After (Secure)
@app.get("/api/invoices/{invoice_id}")
def get_invoice(invoice_id: str, user: User, tenant: TenantContext):
    invoice = db.query(Invoice).filter(
        Invoice.id == invoice_id,
        Invoice.tenant_id == tenant.id  # Tenant filter
    ).first()
    
    if not invoice:
        raise HTTPException(status_code=404)
    
    # Additional object-level check
    if not user.can_access(invoice):
        log_security_event("unauthorized_access_attempt", user, invoice)
        raise HTTPException(status_code=403)
    
    return invoice
```

#### Threat 2: Cache Pollution

**Description:** Tenant A's data is cached without tenant scoping and served to Tenant B.

**Attack Path:**
```
1. Tenant A requests frequently accessed data
2. Data cached with key: "invoice:summary:2024"
3. Tenant B requests same data type
4. Tenant A's data returned from cache
```

**Mitigation:**
```python
# Before (Vulnerable)
cache_key = f"invoice:summary:{year}"

# After (Secure)
cache_key = f"tenant:{tenant_id}:invoice:summary:{year}"

# Cache wrapper with automatic tenant scoping
class TenantAwareCache:
    def __init__(self, redis_client, tenant_context):
        self.redis = redis_client
        self.tenant_id = tenant_context.tenant_id
    
    def _scoped_key(self, key):
        return f"tenant:{self.tenant_id}:{key}"
    
    def get(self, key):
        return self.redis.get(self._scoped_key(key))
    
    def set(self, key, value, ttl=3600):
        self.redis.set(self._scoped_key(key), value, ex=ttl)
```

### Security Requirements Derived from Threat Model

| Requirement ID | Description | Threats Addressed | Priority |
|----------------|-------------|-------------------|----------|
| SEC-001 | All API endpoints must validate tenant context | DATA-01, AUTHZ-03 | Critical |
| SEC-002 | Database RLS must be enabled on all tenant tables | DATA-01 | Critical |
| SEC-003 | Cache keys must include tenant prefix | DATA-05 | High |
| SEC-004 | All admin actions must be audit logged | REP-01 | High |
| SEC-005 | Per-tenant rate limiting must be implemented | DOS-01, DOS-02 | Medium |
| SEC-006 | Webhook signatures must be verified | TAMP-05 | High |
| SEC-007 | JWT tokens must use RS256 and expire in 15 min | AUTH-01 | High |

---

## Quick Reference

### Threat Modeling Checklist

#### Pre-Session
- [ ] Gather architecture diagrams
- [ ] Identify stakeholders to invite
- [ ] Review compliance requirements
- [ ] Collect previous threat models/findings

#### During Session
- [ ] Define system scope and boundaries
- [ ] Create/update data flow diagrams
- [ ] Mark trust boundaries
- [ ] Apply STRIDE to each component
- [ ] Focus on multi-tenant isolation points
- [ ] Rate risks (likelihood × impact)

#### Post-Session
- [ ] Document all identified threats
- [ ] Prioritize by risk score
- [ ] Assign mitigations to owners
- [ ] Create Jira/tickets for implementation
- [ ] Schedule follow-up review

### Multi-Tenant Security Checklist

#### Authentication
- [ ] Tenant ID embedded in tokens
- [ ] Token validation includes tenant verification
- [ ] API keys scoped to tenants
- [ ] SSO configured per-tenant

#### Authorization
- [ ] Object-level authorization on all endpoints
- [ ] Tenant context set on every request
- [ ] RBAC/ABAC for fine-grained access
- [ ] Admin roles isolated per tenant

#### Data Isolation
- [ ] Row-level security enabled
- [ ] All queries include tenant filter
- [ ] Cache keys tenant-prefixed
- [ ] Search indexes tenant-scoped
- [ ] File storage tenant-separated
- [ ] Message queues tenant-routed

#### Logging & Monitoring
- [ ] Cross-tenant access attempts logged
- [ ] Anomaly detection for unusual patterns
- [ ] Audit trail for admin actions
- [ ] Logs don't contain sensitive data

---

## Resources

### Tools
- [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)
- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)
- [STRIDE-GPT](https://github.com/mrwadams/stride-gpt) - AI-powered threat modeling

### Frameworks
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)

### References
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [AWS SaaS Architecture Fundamentals](https://docs.aws.amazon.com/whitepapers/latest/saas-architecture-fundamentals/)
- [Microsoft Multi-Tenant Patterns](https://learn.microsoft.com/en-us/azure/azure-sql/database/saas-tenancy-app-design-patterns)
