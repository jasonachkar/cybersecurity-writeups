# Threat Modeling Templates & Worksheets

Practical templates for conducting threat modeling sessions on multi-tenant SaaS applications.

## Table of Contents

1. [Threat Modeling Session Template](#threat-modeling-session-template)
2. [STRIDE Analysis Worksheet](#stride-analysis-worksheet)
3. [Tenant Isolation Review Checklist](#tenant-isolation-review-checklist)
4. [Risk Register Template](#risk-register-template)
5. [Security Requirements Matrix](#security-requirements-matrix)
6. [Penetration Test Scope for Multi-Tenant](#penetration-test-scope-for-multi-tenant)

---

## Threat Modeling Session Template

### Session Information

| Field | Value |
|-------|-------|
| **Date** | |
| **System/Feature** | |
| **Version/Release** | |
| **Facilitator** | |
| **Participants** | |
| **Duration** | |

### 1. System Overview

**Purpose:**
> Describe what the system does and its business value.

**Tenant Model:**
- [ ] Single-tenant
- [ ] Multi-tenant (Database per tenant)
- [ ] Multi-tenant (Schema per tenant)
- [ ] Multi-tenant (Row-level security)
- [ ] Hybrid

**Data Classification:**
| Data Type | Classification | Regulatory Requirements |
|-----------|----------------|------------------------|
| | | |
| | | |

### 2. Architecture Summary

**Components:**
| Component | Technology | Purpose | Trust Level |
|-----------|------------|---------|-------------|
| | | | |
| | | | |

**Data Stores:**
| Store | Type | Data Stored | Tenant Isolation |
|-------|------|-------------|------------------|
| | | | |

**External Integrations:**
| Integration | Direction | Authentication | Data Exchanged |
|-------------|-----------|----------------|----------------|
| | | | |

### 3. Trust Boundaries

**Identified Boundaries:**
1. 
2. 
3. 

### 4. Assets

**What are we protecting?**
| Asset | Owner | Sensitivity | CIA Priority |
|-------|-------|-------------|--------------|
| | | | C > I > A |
| | | | |

### 5. Threat Identification

*Use STRIDE worksheet for detailed analysis*

### 6. Risk Assessment Summary

| Risk Level | Count | Action |
|------------|-------|--------|
| Critical (15-25) | | Immediate |
| High (10-14) | | This sprint |
| Medium (5-9) | | Next sprint |
| Low (1-4) | | Backlog |

### 7. Action Items

| ID | Action | Owner | Due Date | Status |
|----|--------|-------|----------|--------|
| | | | | |

### 8. Next Review

**Triggers for re-review:**
- [ ] Architecture changes
- [ ] New integrations
- [ ] Compliance requirement changes
- [ ] Major incident

**Scheduled review date:** _______________

---

## STRIDE Analysis Worksheet

### How to Use

For each component/data flow in your DFD, ask the STRIDE questions below.

---

### Component: _______________________

#### Spoofing (Authentication)

**Question:** Can an attacker pretend to be someone/something else?

| Threat | Applicable? | Description | Likelihood | Impact | Risk |
|--------|-------------|-------------|------------|--------|------|
| User impersonation | Y/N | | 1-5 | 1-5 | L×I |
| Service impersonation | Y/N | | | | |
| Token/credential theft | Y/N | | | | |
| Session hijacking | Y/N | | | | |
| API key compromise | Y/N | | | | |
| Tenant impersonation | Y/N | | | | |

**Existing Controls:**
- 

**Recommended Mitigations:**
- 

---

#### Tampering (Integrity)

**Question:** Can an attacker modify data they shouldn't?

| Threat | Applicable? | Description | Likelihood | Impact | Risk |
|--------|-------------|-------------|------------|--------|------|
| Data modification | Y/N | | 1-5 | 1-5 | L×I |
| SQL injection | Y/N | | | | |
| Parameter manipulation | Y/N | | | | |
| Mass assignment | Y/N | | | | |
| Message tampering | Y/N | | | | |
| Configuration changes | Y/N | | | | |

**Existing Controls:**
- 

**Recommended Mitigations:**
- 

---

#### Repudiation (Non-repudiation)

**Question:** Can an attacker deny their actions?

| Threat | Applicable? | Description | Likelihood | Impact | Risk |
|--------|-------------|-------------|------------|--------|------|
| Missing audit logs | Y/N | | 1-5 | 1-5 | L×I |
| Log tampering | Y/N | | | | |
| Insufficient attribution | Y/N | | | | |
| Time manipulation | Y/N | | | | |
| Anonymous actions | Y/N | | | | |

**Existing Controls:**
- 

**Recommended Mitigations:**
- 

---

#### Information Disclosure (Confidentiality)

**Question:** Can an attacker access data they shouldn't?

| Threat | Applicable? | Description | Likelihood | Impact | Risk |
|--------|-------------|-------------|------------|--------|------|
| Cross-tenant data access | Y/N | | 1-5 | 1-5 | L×I |
| IDOR vulnerability | Y/N | | | | |
| Error message leakage | Y/N | | | | |
| Log exposure | Y/N | | | | |
| Cache leakage | Y/N | | | | |
| Backup exposure | Y/N | | | | |
| API over-exposure | Y/N | | | | |
| Search index leakage | Y/N | | | | |

**Existing Controls:**
- 

**Recommended Mitigations:**
- 

---

#### Denial of Service (Availability)

**Question:** Can an attacker disrupt service?

| Threat | Applicable? | Description | Likelihood | Impact | Risk |
|--------|-------------|-------------|------------|--------|------|
| Resource exhaustion | Y/N | | 1-5 | 1-5 | L×I |
| Noisy neighbor | Y/N | | | | |
| Rate limit bypass | Y/N | | | | |
| Connection exhaustion | Y/N | | | | |
| Storage exhaustion | Y/N | | | | |
| Background job flooding | Y/N | | | | |

**Existing Controls:**
- 

**Recommended Mitigations:**
- 

---

#### Elevation of Privilege (Authorization)

**Question:** Can an attacker gain unauthorized access?

| Threat | Applicable? | Description | Likelihood | Impact | Risk |
|--------|-------------|-------------|------------|--------|------|
| Horizontal escalation | Y/N | | 1-5 | 1-5 | L×I |
| Vertical escalation | Y/N | | | | |
| Tenant admin takeover | Y/N | | | | |
| Role manipulation | Y/N | | | | |
| Missing function-level authz | Y/N | | | | |
| Privilege inheritance | Y/N | | | | |

**Existing Controls:**
- 

**Recommended Mitigations:**
- 

---

## Tenant Isolation Review Checklist

### Authentication Layer

| Check | Status | Notes |
|-------|--------|-------|
| Tenant ID included in JWT/session | ☐ Pass ☐ Fail ☐ N/A | |
| Token validation includes tenant check | ☐ Pass ☐ Fail ☐ N/A | |
| API keys scoped to specific tenant | ☐ Pass ☐ Fail ☐ N/A | |
| SSO/SAML configured per tenant | ☐ Pass ☐ Fail ☐ N/A | |
| MFA enforced for tenant admins | ☐ Pass ☐ Fail ☐ N/A | |

### Authorization Layer

| Check | Status | Notes |
|-------|--------|-------|
| Tenant context set on every request | ☐ Pass ☐ Fail ☐ N/A | |
| Object-level authorization implemented | ☐ Pass ☐ Fail ☐ N/A | |
| All endpoints verify tenant ownership | ☐ Pass ☐ Fail ☐ N/A | |
| Admin roles isolated per tenant | ☐ Pass ☐ Fail ☐ N/A | |
| Super-admin access is audited | ☐ Pass ☐ Fail ☐ N/A | |

### Database Layer

| Check | Status | Notes |
|-------|--------|-------|
| Row-level security (RLS) enabled | ☐ Pass ☐ Fail ☐ N/A | |
| All tables have tenant_id column | ☐ Pass ☐ Fail ☐ N/A | |
| RLS policies applied to all tenant tables | ☐ Pass ☐ Fail ☐ N/A | |
| Database connections scoped to tenant | ☐ Pass ☐ Fail ☐ N/A | |
| Cross-tenant JOINs prevented | ☐ Pass ☐ Fail ☐ N/A | |
| Migrations tested for RLS compliance | ☐ Pass ☐ Fail ☐ N/A | |

### Application Layer

| Check | Status | Notes |
|-------|--------|-------|
| ORM/query builder enforces tenant filter | ☐ Pass ☐ Fail ☐ N/A | |
| Manual queries include tenant filter | ☐ Pass ☐ Fail ☐ N/A | |
| Bulk operations scoped to tenant | ☐ Pass ☐ Fail ☐ N/A | |
| Export functions filtered by tenant | ☐ Pass ☐ Fail ☐ N/A | |
| Search results scoped to tenant | ☐ Pass ☐ Fail ☐ N/A | |
| File uploads stored in tenant-specific path | ☐ Pass ☐ Fail ☐ N/A | |

### Caching Layer

| Check | Status | Notes |
|-------|--------|-------|
| Cache keys include tenant prefix | ☐ Pass ☐ Fail ☐ N/A | |
| CDN cache varies by tenant | ☐ Pass ☐ Fail ☐ N/A | |
| Session storage is tenant-isolated | ☐ Pass ☐ Fail ☐ N/A | |
| No shared cache between tenants | ☐ Pass ☐ Fail ☐ N/A | |

### Queue/Background Jobs

| Check | Status | Notes |
|-------|--------|-------|
| Messages include tenant context | ☐ Pass ☐ Fail ☐ N/A | |
| Workers validate tenant before processing | ☐ Pass ☐ Fail ☐ N/A | |
| Job queues are tenant-isolated (if required) | ☐ Pass ☐ Fail ☐ N/A | |
| Scheduled jobs run in correct tenant context | ☐ Pass ☐ Fail ☐ N/A | |

### Logging & Monitoring

| Check | Status | Notes |
|-------|--------|-------|
| Logs include tenant_id | ☐ Pass ☐ Fail ☐ N/A | |
| Alerts for cross-tenant access attempts | ☐ Pass ☐ Fail ☐ N/A | |
| Tenant-specific dashboards available | ☐ Pass ☐ Fail ☐ N/A | |
| No sensitive data in logs | ☐ Pass ☐ Fail ☐ N/A | |

### External Integrations

| Check | Status | Notes |
|-------|--------|-------|
| Webhook payloads scoped to tenant | ☐ Pass ☐ Fail ☐ N/A | |
| OAuth tokens are tenant-specific | ☐ Pass ☐ Fail ☐ N/A | |
| Third-party data isolated by tenant | ☐ Pass ☐ Fail ☐ N/A | |
| API callbacks verify tenant origin | ☐ Pass ☐ Fail ☐ N/A | |

---

## Risk Register Template

### Risk Entry Format

```yaml
- id: RISK-001
  title: "Cross-Tenant Data Access via IDOR"
  description: |
    Users can access resources belonging to other tenants by 
    manipulating object IDs in API requests.
  category: "Information Disclosure"
  stride: "I"
  
  # Risk Assessment
  likelihood: 4  # 1-5
  impact: 5      # 1-5
  risk_score: 20 # likelihood × impact
  risk_level: "Critical"  # Low/Medium/High/Critical
  
  # Attack Details
  attack_vector: "API manipulation"
  prerequisites:
    - "Authenticated user account"
    - "Knowledge of resource ID format"
  affected_assets:
    - "Invoice data"
    - "Customer records"
  
  # Compliance Impact
  compliance:
    - "GDPR Article 32 - Data security"
    - "SOC 2 CC6.1 - Access control"
  
  # Mitigation
  mitigations:
    - id: MIT-001
      description: "Implement object-level authorization"
      status: "In Progress"
      owner: "Backend Team"
      due_date: "2025-02-01"
    - id: MIT-002
      description: "Add tenant context validation middleware"
      status: "Planned"
      owner: "Platform Team"
      due_date: "2025-02-15"
  
  # Tracking
  identified_date: "2025-01-07"
  identified_by: "Threat Model Session"
  status: "Open"
  residual_risk: "Low"  # After mitigations
  
  # References
  references:
    - "OWASP API Security Top 10 - API1: BOLA"
    - "CWE-639: Authorization Bypass"
```

### Risk Register Summary Table

| ID | Title | STRIDE | Likelihood | Impact | Risk Score | Status | Owner |
|----|-------|--------|------------|--------|------------|--------|-------|
| RISK-001 | Cross-Tenant IDOR | I | 4 | 5 | 20 (Critical) | Open | Backend |
| RISK-002 | JWT Token Forgery | S | 2 | 5 | 10 (High) | Mitigated | Security |
| RISK-003 | Missing Audit Logs | R | 3 | 3 | 9 (Medium) | In Progress | Platform |
| RISK-004 | Noisy Neighbor DoS | D | 4 | 3 | 12 (High) | Open | Infra |
| RISK-005 | Horizontal Escalation | E | 3 | 4 | 12 (High) | Open | Backend |

---

## Security Requirements Matrix

### Mapping Threats to Requirements

| Threat ID | Threat Description | Requirement ID | Requirement | Control Type | Priority |
|-----------|-------------------|----------------|-------------|--------------|----------|
| AUTH-01 | JWT forgery | SEC-REQ-001 | Use RS256 for JWT signing | Preventive | Critical |
| AUTH-01 | JWT forgery | SEC-REQ-002 | JWT expiry ≤ 15 minutes | Preventive | High |
| DATA-01 | Cross-tenant IDOR | SEC-REQ-003 | Object-level authorization | Preventive | Critical |
| DATA-01 | Cross-tenant IDOR | SEC-REQ-004 | Tenant context middleware | Preventive | Critical |
| DATA-05 | Cache pollution | SEC-REQ-005 | Tenant-prefixed cache keys | Preventive | High |
| DOS-01 | Noisy neighbor | SEC-REQ-006 | Per-tenant rate limiting | Preventive | Medium |
| DOS-01 | Noisy neighbor | SEC-REQ-007 | Resource quotas per tenant | Preventive | Medium |
| AUTHZ-01 | Horizontal escalation | SEC-REQ-008 | RBAC enforcement | Preventive | High |
| REP-01 | Missing audit | SEC-REQ-009 | Audit all admin actions | Detective | High |
| REP-01 | Missing audit | SEC-REQ-010 | Immutable audit log storage | Preventive | Medium |

### Requirement Details

#### SEC-REQ-003: Object-Level Authorization

**Description:** Every API endpoint that accesses tenant-specific resources must verify that the requesting user has permission to access the specific object.

**Implementation Guidance:**
```python
# Required checks for every resource endpoint:
# 1. Authenticate the user
# 2. Resolve the tenant context
# 3. Fetch the resource WITH tenant filter
# 4. Verify user has permission on this object

@requires_auth
@requires_tenant_context
def get_resource(resource_id: str, user: User, tenant: Tenant):
    # Fetch with tenant filter
    resource = db.query(Resource).filter(
        Resource.id == resource_id,
        Resource.tenant_id == tenant.id  # CRITICAL
    ).first()
    
    if not resource:
        raise NotFoundError()  # Don't reveal existence
    
    # Check object-level permission
    if not permissions.can_read(user, resource):
        raise ForbiddenError()
    
    return resource
```

**Verification:**
- [ ] Unit tests cover authorization checks
- [ ] Integration tests attempt cross-tenant access
- [ ] Penetration test includes IDOR testing
- [ ] Code review checklist includes authz verification

---

## Penetration Test Scope for Multi-Tenant

### Test Categories

#### Category 1: Tenant Isolation Testing

**Objective:** Verify that tenants cannot access each other's data or resources.

| Test ID | Test Case | Method | Expected Result |
|---------|-----------|--------|-----------------|
| ISO-001 | Access another tenant's resource via IDOR | Modify resource IDs in API requests | 403 Forbidden or 404 Not Found |
| ISO-002 | Enumerate other tenants' resources | Sequential/random ID guessing | No valid responses for other tenants |
| ISO-003 | Access via cached data | Analyze cache behavior | No cross-tenant cache leakage |
| ISO-004 | Search for other tenants' data | Full-text search manipulation | Results limited to current tenant |
| ISO-005 | Access via export functions | Export data, check contents | Only current tenant data |
| ISO-006 | Access via background jobs | Trigger jobs, analyze data flow | Jobs scoped to triggering tenant |

#### Category 2: Authentication Testing

| Test ID | Test Case | Method | Expected Result |
|---------|-----------|--------|-----------------|
| AUTH-001 | JWT token manipulation | Modify tenant_id claim | Token rejected |
| AUTH-002 | Token reuse across tenants | Use Tenant A token for Tenant B | Authentication failure |
| AUTH-003 | API key scope bypass | Use key across tenants | Unauthorized |
| AUTH-004 | Session fixation | Fix session, login as victim | Attack prevented |
| AUTH-005 | SSO tenant bypass | SAML/OIDC manipulation | Proper tenant validation |

#### Category 3: Authorization Testing

| Test ID | Test Case | Method | Expected Result |
|---------|-----------|--------|-----------------|
| AUTHZ-001 | Horizontal privilege escalation | Access other user's resources | 403 Forbidden |
| AUTHZ-002 | Vertical privilege escalation | Attempt admin functions | 403 Forbidden |
| AUTHZ-003 | Role manipulation | Modify role claims/parameters | Changes rejected |
| AUTHZ-004 | Function-level access control | Direct endpoint access | Proper authorization |
| AUTHZ-005 | Mass assignment | Submit tenant_id in request body | Ignored/rejected |

#### Category 4: Availability Testing

| Test ID | Test Case | Method | Expected Result |
|---------|-----------|--------|-----------------|
| AVAIL-001 | Rate limit effectiveness | High-volume requests | Proper rate limiting |
| AVAIL-002 | Per-tenant rate limits | Exhaust one tenant's quota | Other tenants unaffected |
| AVAIL-003 | Resource quotas | Exceed storage/compute limits | Quota enforcement |
| AVAIL-004 | Large payload handling | Submit oversized requests | Proper limits applied |

### Test Account Matrix

| Account Type | Tenant | Purpose |
|--------------|--------|---------|
| Attacker User A | Tenant-Alpha | Primary attacker account |
| Victim User B | Tenant-Beta | Target for cross-tenant tests |
| Admin User A | Tenant-Alpha | Escalation target within tenant |
| Super Admin | Platform | Platform-level privilege tests |
| API Key A | Tenant-Alpha | API authentication tests |
| API Key B | Tenant-Beta | Cross-tenant API tests |

### Evidence Requirements

For each finding:
- [ ] Clear reproduction steps
- [ ] HTTP request/response (redacted)
- [ ] Screenshot or video evidence
- [ ] Impact assessment
- [ ] CVSS score
- [ ] Recommended remediation
- [ ] Verification of fix

---

## Security Control Mapping

### STRIDE to Controls Matrix

| STRIDE | Control Category | Specific Controls |
|--------|-----------------|-------------------|
| **Spoofing** | Authentication | MFA, Strong passwords, Token binding, Session management |
| **Tampering** | Integrity | Input validation, Parameterized queries, Digital signatures, Checksums |
| **Repudiation** | Non-repudiation | Audit logging, Log integrity, Timestamps, Digital signatures |
| **Information Disclosure** | Confidentiality | Encryption (transit/rest), Access control, Data masking, RLS |
| **Denial of Service** | Availability | Rate limiting, Resource quotas, Load balancing, Auto-scaling |
| **Elevation of Privilege** | Authorization | RBAC/ABAC, Least privilege, Object-level authz, Tenant isolation |

### Control Effectiveness Testing

| Control | Test Method | Pass Criteria |
|---------|-------------|---------------|
| JWT RS256 signing | Attempt HS256 downgrade | Algorithm enforced |
| RLS policies | Direct DB query without context | Query blocked/filtered |
| Rate limiting | Exceed limits | 429 returned, requests blocked |
| Audit logging | Perform sensitive action | Action logged with full context |
| Object-level authz | Access unowned resource | 403/404 returned |
| Input validation | Submit malformed data | Request rejected |

---

## Appendix: STRIDE Quick Reference Cards

### Card 1: Spoofing

```
┌─────────────────────────────────────────────────────────────┐
│  SPOOFING - Can an attacker impersonate?                    │
├─────────────────────────────────────────────────────────────┤
│  Property Violated: AUTHENTICATION                          │
│                                                             │
│  Questions to Ask:                                          │
│  • How do we verify user identity?                          │
│  • How do we verify service identity?                       │
│  • Can tokens/credentials be forged?                        │
│  • Can sessions be hijacked?                                │
│  • Can tenant context be spoofed?                           │
│                                                             │
│  Common Attacks:                                            │
│  • Token forgery          • Session fixation                │
│  • Credential stuffing    • API key theft                   │
│  • SAML manipulation      • Tenant impersonation            │
│                                                             │
│  Mitigations:                                               │
│  • Strong authentication (MFA)                              │
│  • Cryptographic token signing                              │
│  • Session binding                                          │
│  • Tenant context validation                                │
└─────────────────────────────────────────────────────────────┘
```

### Card 2: Information Disclosure

```
┌─────────────────────────────────────────────────────────────┐
│  INFORMATION DISCLOSURE - Can data leak?                    │
├─────────────────────────────────────────────────────────────┤
│  Property Violated: CONFIDENTIALITY                         │
│                                                             │
│  Questions to Ask:                                          │
│  • Can Tenant A access Tenant B's data?                     │
│  • What data is exposed in errors?                          │
│  • Is sensitive data logged?                                │
│  • Can cache serve wrong tenant's data?                     │
│  • Are backups properly isolated?                           │
│                                                             │
│  Common Attacks:                                            │
│  • Cross-tenant IDOR      • Error message analysis          │
│  • Log harvesting         • Cache poisoning                 │
│  • Search index abuse     • Backup theft                    │
│                                                             │
│  Mitigations:                                               │
│  • Row-level security                                       │
│  • Tenant-scoped queries                                    │
│  • Generic error messages                                   │
│  • Tenant-prefixed caching                                  │
│  • Encryption at rest                                       │
└─────────────────────────────────────────────────────────────┘
```

### Card 3: Elevation of Privilege

```
┌─────────────────────────────────────────────────────────────┐
│  ELEVATION OF PRIVILEGE - Can access be escalated?          │
├─────────────────────────────────────────────────────────────┤
│  Property Violated: AUTHORIZATION                           │
│                                                             │
│  Questions to Ask:                                          │
│  • Can users access others' resources? (horizontal)         │
│  • Can users gain admin access? (vertical)                  │
│  • Can users become another tenant's admin?                 │
│  • Are all functions properly authorized?                   │
│  • Can roles/permissions be manipulated?                    │
│                                                             │
│  Common Attacks:                                            │
│  • IDOR exploitation      • Role injection                  │
│  • Mass assignment        • Function-level bypass           │
│  • Tenant context switch  • Admin API access                │
│                                                             │
│  Mitigations:                                               │
│  • Object-level authorization                               │
│  • RBAC/ABAC enforcement                                    │
│  • Tenant context validation                                │
│  • Least privilege principle                                │
│  • Admin function isolation                                 │
└─────────────────────────────────────────────────────────────┘
```
