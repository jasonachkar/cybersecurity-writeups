---
title: "Securing Azure Entra ID: A Zero Trust Approach"
type: tutorial
tags: [Azure, Entra ID, IAM, Zero Trust, Identity Security, Conditional Access, PIM]
date: 2024-05
readingTime: 25
---

# Securing Azure Entra ID (formerly Azure AD): A Zero Trust Approach

## Introduction

In modern cloud environments, identity is the primary security perimeter. Traditional network-based defenses are no longer sufficient when users, devices, and workloads operate from anywhere. As a result, identity systems have become the most targeted attack surface.

This tutorial documents a practical, security-first approach to hardening Azure Entra ID using Zero Trust principles. The focus is on real-world identity threats, common misconfigurations, and how to use Entra ID's native controls to reduce account compromise and privilege abuse.

According to Microsoft's Digital Defense Report 2024, they analyze over 78 trillion security signals daily and block approximately 4,000 password attacks every second. This underscores the critical importance of properly securing identity infrastructure.

---

## Why Identity Is the New Perimeter

In cloud-native architectures:

- Applications are internet-facing by default
- Users authenticate from unmanaged networks
- VPNs are no longer universal
- Attackers target credentials rather than infrastructure
- BYOD policies and remote work expand the attack surface

If identity is compromised, attackers can often bypass network controls entirely. Microsoft studies indicate that accounts protected with MFA are 99.9% less likely to be compromised. Securing Entra ID is therefore foundational to cloud security.

---

## Zero Trust Principles Applied to Identity

Zero Trust is not a product — it is a design philosophy. Applied to identity, it consists of four core principles:

### 1. Verify Explicitly

Always authenticate and authorize based on all available data points including user identity, location, device health, service or workload, data classification, and anomalies.

### 2. Use Least Privilege

Limit user access with Just-In-Time (JIT) and Just-Enough-Access (JEA), risk-based adaptive policies, and data protection measures.

### 3. Assume Breach

Minimize blast radius and segment access. Verify end-to-end encryption and use analytics to detect threats, improve defenses, and drive visibility.

### 4. Continuously Evaluate Trust

Access decisions should be dynamic, reassessing trust in real-time based on changing conditions rather than relying on a one-time authentication event.

Every Entra ID configuration decision in this guide maps back to these principles.

---

## Identity Threat Landscape

Common identity-based attack techniques include:

### Credential-Based Attacks
- **Credential phishing**: Attackers create fake login pages to steal credentials
- **Password spraying**: Attempting common passwords across many accounts
- **Credential stuffing**: Using leaked credentials from other breaches
- **Brute force attacks**: Systematically trying password combinations

### Token-Based Attacks
- **Token theft**: Stealing OAuth tokens from browsers or applications
- **Token replay**: Reusing valid tokens from compromised sessions
- **Pass-the-Token**: Using stolen tokens to access resources

### Social Engineering
- **MFA fatigue attacks**: Repeatedly sending MFA prompts until user accepts
- **Consent phishing**: Tricking users into granting app permissions
- **Business Email Compromise (BEC)**: Impersonating executives for fraudulent requests

### Privilege Escalation
- **Role abuse**: Exploiting overly permissive role assignments
- **Lateral movement**: Using compromised accounts to access other resources
- **Service principal compromise**: Targeting application identities

Most successful cloud breaches involve identity compromise, not zero-day exploits. MITRE ATT&CK techniques T1110 (Brute Force), T1078 (Valid Accounts), and T1528 (Steal Application Access Token) are among the most commonly observed.

---

## Baseline Identity Hardening

### Enforce Strong Authentication

The first line of defense is strong authentication. As of October 1, 2025, Azure has entered Phase 2 of mandatory MFA enforcement, requiring strong authentication for all Azure service users including CLI, PowerShell, Azure mobile app, IaC tools, and REST API endpoints.

#### Key Controls

**1. Enforce Multi-Factor Authentication (MFA) for All Users**

```
Recommendation: Require MFA for 100% of users
Implementation: Conditional Access policy targeting all users
Exclusions: Only break-glass/emergency access accounts
```

**2. Block Legacy Authentication Protocols**

Legacy authentication bypasses modern security controls and should be disabled entirely. Users are 10x more likely to be compromised when using legacy protocols.

```
Protocols to Block:
- IMAP
- POP3
- SMTP AUTH
- Basic Auth for Exchange Online
- Exchange ActiveSync with Basic Auth
```

**3. Require Phishing-Resistant MFA for Privileged Roles**

For high-privilege accounts, standard MFA may not be sufficient.

```
Phishing-Resistant Methods:
- FIDO2 Security Keys
- Windows Hello for Business
- Microsoft Entra ID Certificate-Based Authentication (CBA)
- Device-bound passkeys
```

**4. Enable Microsoft Entra Password Protection**

Deploy password protection to block commonly used and organization-specific weak passwords both in the cloud and on-premises via agents.

---

## Conditional Access Policy Design

Conditional Access (CA) is the primary enforcement mechanism for Zero Trust in Entra ID. It acts as the "if-then" policy engine that brings signals together to make decisions and enforce organizational policies.

### Core Policy Categories

#### Category 1: Secure Foundations (Deploy First)

These policies form the baseline and should be deployed as a group:

| Policy | Target | Condition | Grant Control |
|--------|--------|-----------|---------------|
| Require MFA for all users | All users | All cloud apps | Require MFA |
| Block legacy authentication | All users | Exchange ActiveSync clients, Other clients | Block access |
| Require MFA for Azure management | All users | Azure Resource Manager | Require MFA |
| Require compliant or hybrid joined device | All users | All cloud apps | Require compliant device OR Hybrid Azure AD joined |

#### Category 2: Zero Trust Policies

| Policy | Target | Condition | Grant Control |
|--------|--------|-----------|---------------|
| Require MFA for admins | Directory roles | All cloud apps | Require authentication strength: Phishing-resistant MFA |
| Block high-risk sign-ins | All users | Sign-in risk: High | Block access |
| Block high-risk users | All users | User risk: High | Block access OR Require password change |
| Require MFA for risky sign-ins | All users | Sign-in risk: Medium | Require MFA |

#### Category 3: Secure Remote Workers

| Policy | Target | Condition | Grant Control |
|--------|--------|-----------|---------------|
| Require approved apps on mobile | All users | iOS, Android | Require approved client app |
| Require app protection policy | All users | iOS, Android | Require app protection policy |
| Block access from untrusted locations | Admin roles | Locations: Not trusted | Block access |

#### Category 4: Protect Administrators

| Policy | Target | Condition | Grant Control |
|--------|--------|-----------|---------------|
| Require phishing-resistant MFA for admins | Global Admin, Security Admin, etc. | All cloud apps | Authentication strength: Phishing-resistant |
| Require compliant device for admins | Admin roles | All cloud apps | Require compliant device |
| Block admin access from untrusted countries | Admin roles | Countries: Not allowed list | Block access |

### Conditional Access Design Best Practices

**1. Always Deploy in Report-Only Mode First**

Every new policy should be tested in report-only mode to understand its impact before enforcement.

**2. Use the What If Tool**

The What If tool allows you to simulate sign-in scenarios without affecting real users.

**3. Exclude Emergency Access Accounts**

Always exclude at least two break-glass accounts from all Conditional Access policies.

**4. Cover All Applications**

Create policies targeting "All resources" rather than individual apps to prevent blind spots. Attackers may use unprotected apps as entry points.

**5. Use Named Locations**

Define trusted network locations to reduce false positives in risk detections and enable location-based policies.

**6. Separate Mobile and Desktop Policies**

Consider splitting policies targeting mobile devices (iOS/Android) and computers (Windows/macOS) for clearer reporting and management.

### Microsoft-Managed Policies

Microsoft now provides Microsoft-managed Conditional Access policies that are automatically deployed to tenants. These policies:

- Require MFA and align with Microsoft recommendations
- Are enabled 45 days after introduction if left in report-only mode
- Can be customized to exclude specific accounts
- Should be reviewed and integrated into your policy strategy

---

## Privileged Identity Management (PIM)

Standing administrative access is one of the highest-risk identity configurations. If an admin account is compromised, attackers gain immediate control, detection is often delayed, and damage is widespread.

### Why PIM Matters

Microsoft recommends assigning the Global Administrator role to fewer than five people in your organization. Privileged Identity Management (PIM) provides time-based and approval-based role activation to mitigate risks of excessive, unnecessary, or misused access permissions.

### Key PIM Features

- **Just-in-Time (JIT) access**: Users activate roles only when needed
- **Time-bound assignments**: Privileges expire automatically
- **Approval workflows**: Require approval for sensitive role activations
- **MFA on activation**: Require MFA when activating privileged roles
- **Justification requirements**: Users must provide reasons for access
- **Audit trails**: Complete history of all privilege activations

### PIM Best Practices

**1. Extend JIT to All Roles**

While JIT is usually associated with high-impact roles, extending this model to all roles offers better security and helps normalize secure behaviors throughout the organization.

**2. Configure Short Activation Durations**

The activation duration should be just long enough for users to complete their privileged task. Start with 4 hours and adjust based on operational feedback. Never use the maximum 24-hour duration.

```
Recommended Activation Durations:
- Global Administrator: 1-2 hours (with approval)
- Security Administrator: 2-4 hours (with approval)
- Exchange Administrator: 4-8 hours
- Helpdesk Administrator: 4-8 hours
- User Administrator: 4-8 hours
```

**3. Require Approval for High-Impact Roles**

Configure approval requirements for roles with the most potential for damage:

```
Roles Requiring Approval:
- Global Administrator
- Privileged Role Administrator
- Security Administrator
- Exchange Administrator
- SharePoint Administrator
```

**4. Use PIM for Groups**

Instead of assigning roles directly to users, create groups managed by PIM. This allows:
- Different policies for different user personas (internal vs. contractor)
- Single activation for access to multiple roles
- Cleaner audit trails

**5. Configure Alerts and Reviews**

Enable PIM alerts for:
- Roles being activated outside of PIM
- Excessive role activations
- Stale role assignments
- Permanent active assignments

**6. Conduct Regular Access Reviews**

Combine PIM with Access Reviews to:
- Regularly review and revoke unnecessary access
- Prevent "privilege creep" over time
- Meet compliance requirements

### PIM Role Settings Configuration

For each role managed by PIM, configure:

| Setting | Recommendation |
|---------|----------------|
| Activation maximum duration | 4-8 hours (role-dependent) |
| Require MFA on activation | Yes |
| Require justification | Yes |
| Require ticket information | Optional (for change management) |
| Require approval | Yes (for high-impact roles) |
| Allow permanent eligible assignment | No (use time-bound) |
| Allow permanent active assignment | No (except break-glass) |

---

## Role-Based Access Control (RBAC)

### Least Privilege by Design

RBAC should be applied consistently across:
- Entra ID directory roles
- Azure resource roles (subscriptions, resource groups)
- Application-specific roles

### Roles to Avoid

Broad roles create unnecessary risk. Avoid routine use of:

| Role | Risk | Alternative |
|------|------|-------------|
| Global Administrator | Full tenant control | Use specific admin roles |
| Owner | Full resource control | Contributor + UAA where needed |
| Contributor | Broad resource access | Custom role with specific permissions |
| User Access Administrator | Can grant any access | Assign at lowest scope possible |

### RBAC Best Practices

**1. Use Built-In Roles Where Possible**

Microsoft provides 80+ built-in roles covering most scenarios. Custom roles should be created only when necessary.

**2. Assign Roles at the Lowest Scope**

Always assign roles at the lowest scope (resource > resource group > subscription > management group).

**3. Use Groups for Role Assignments**

Assign roles to groups rather than individuals to simplify management and enable PIM for Groups.

**4. Avoid On-Premises Synced Accounts for Admin Roles**

Cloud-only accounts should be used for administrative purposes. If an on-premises account is compromised, it can compromise Microsoft Entra resources.

**5. Remove Microsoft Accounts from Admin Roles**

Personal Microsoft accounts (outlook.com, hotmail.com) should never hold administrative privileges. Replace with organizational accounts.

---

## Securing Application Identities

Applications and service principals are often overlooked attack vectors. They operate non-interactively and can have broad permissions.

### Common Risks

- Over-permissioned app registrations
- Long-lived client secrets (years instead of months)
- Unmonitored API permissions
- Unused or orphaned applications

### Hardening Measures

**1. Use Managed Identities**

For Azure workloads, always use managed identities instead of secrets or certificates. Managed identities:
- Eliminate credential management
- Automatically rotate credentials
- Cannot be used outside Azure

**2. Implement Short Secret Lifetimes**

When secrets are necessary:
```
Recommended Secret Lifetimes:
- Maximum: 12 months
- Recommended: 6 months or less
- Use certificates instead of secrets where possible
```

**3. Restrict API Permissions**

- Request only necessary permissions
- Prefer delegated permissions over application permissions
- Implement admin consent workflows
- Review granted permissions regularly

**4. Control Application Registration**

Configure tenant settings to:
- Restrict users from creating app registrations
- Require admin consent for new applications
- Implement consent workflows for user-requested apps

**5. Monitor Application Activity**

Track:
- Consent grants
- Permission changes
- API access patterns
- Sign-in anomalies for service principals

### Conditional Access for Workload Identities

Entra ID now supports Conditional Access for workload identities (service principals). Configure policies to:
- Restrict service principal sign-ins to specific IP ranges
- Block risky workload identities
- Require specific conditions for application access

---

## Emergency Access Accounts (Break-Glass)

Emergency access accounts are critical for recovery scenarios. Without them, policy misconfiguration or service outages could lock out all administrators.

### Configuration Requirements

**1. Create At Least Two Accounts**

```
Naming Convention:
- EmergencyAccess1@domain.com
- EmergencyAccess2@domain.com
```

**2. Account Properties**

| Property | Setting |
|----------|---------|
| Account type | Cloud-only (not synced) |
| Role assignment | Global Administrator (permanent active) |
| MFA | Exempt from Conditional Access |
| Password | Long, complex, randomly generated |
| Password expiration | Never |
| Sign-in logging | Monitored with alerts |

**3. Credential Storage**

- Store credentials in a physical safe or secure vault
- Split credentials between multiple secure locations
- Document access procedures
- Conduct regular access tests

**4. Monitoring**

Create alerts for:
- Any sign-in to break-glass accounts
- Password changes on break-glass accounts
- Role assignment changes to break-glass accounts

---

## Identity Protection Configuration

Microsoft Entra ID Protection uses machine learning to detect suspicious activity and automate remediation.

### Risk-Based Policies

#### User Risk Policy

User risk represents the probability that an account has been compromised.

```
Recommended Configuration:
- Risk level trigger: High
- Action: Require secure password change
- Users: All users
- Exclusions: Break-glass accounts
```

#### Sign-In Risk Policy

Sign-in risk represents the probability that a specific authentication request is not authorized.

```
Recommended Configuration:
- Risk level trigger: Medium and High
- Action: Require MFA (for Medium), Block (for High)
- Users: All users
- Exclusions: Break-glass accounts
```

### Risk Detections

Identity Protection detects various risk types:

**Real-Time Detections:**
- Anonymous IP address
- Atypical travel
- Malware-linked IP address
- Unfamiliar sign-in properties
- Admin confirmed user compromised

**Offline Detections:**
- Leaked credentials
- Password spray
- Impossible travel
- New country
- Activity from anonymous IP address

### Best Practices for Identity Protection

**1. Use Conditional Access for Risk Policies**

Configure risk policies through Conditional Access rather than legacy Identity Protection policies for:
- Enhanced diagnostic data
- Report-only mode capability
- Graph API support
- Additional policy conditions

**2. Configure Trusted Locations**

Properly configured named locations reduce false positives in risk detections.

**3. Enable Self-Remediation**

Allow users to self-remediate low and medium risks through:
- MFA challenge for sign-in risk
- Secure password change for user risk

**4. Don't Combine Risk Types**

Create separate Conditional Access policies for user risk and sign-in risk. Combining them in one policy can create unexpected behavior.

---

## Monitoring and Detection

### Key Logs to Collect

| Log Type | Purpose | Retention |
|----------|---------|-----------|
| Sign-in logs | Authentication events | 30+ days |
| Audit logs | Configuration changes | 30+ days |
| Risk events | Identity Protection detections | 30+ days |
| Provisioning logs | User/group sync events | 30+ days |

### SIEM Integration

Forward logs to your SIEM (Microsoft Sentinel, Splunk, etc.) for:
- Centralized analysis
- Correlation with other security data
- Long-term retention
- Custom detection rules

### Detection Scenarios

**1. Impossible Travel**

Alert when a user authenticates from geographically impossible locations within a short timeframe.

**2. MFA Bypass Attempts**

Alert on successful authentications that bypass MFA unexpectedly.

**3. Privilege Escalation**

Alert on:
- Role assignment changes
- PIM activations (especially outside business hours)
- Changes to Conditional Access policies

**4. Token Abuse**

Alert on:
- Token usage without corresponding interactive sign-in
- High-frequency API calls from service principals
- Token usage from unexpected locations

---

## Identity Governance and Lifecycle Management

Security is not static. Identity governance ensures access remains appropriate over time.

### Access Reviews

Configure regular access reviews for:
- Privileged role assignments
- Group memberships
- Application access
- Guest user access

```
Review Cadence:
- Global Administrator: Monthly
- Other privileged roles: Quarterly
- Application access: Quarterly to Annually
- Guest users: Quarterly
```

### Entitlement Management

Use entitlement management for:
- Self-service access requests
- Automated provisioning
- Time-limited access packages
- Access expiration and renewal

### Lifecycle Workflows

Automate identity lifecycle events:
- Joiner: Provision accounts and baseline access
- Mover: Adjust access when roles change
- Leaver: Deprovision and revoke access

---

## Common Misconfigurations to Avoid

| Misconfiguration | Risk | Remediation |
|-----------------|------|-------------|
| Legacy authentication enabled | Bypasses MFA | Create CA policy to block |
| Permanent admin access | Extended attack window | Implement PIM |
| No monitoring of identity logs | Blind to attacks | Forward to SIEM |
| Overly permissive app permissions | Data exposure | Audit and restrict |
| MFA only for admins | User accounts vulnerable | MFA for all users |
| No emergency access accounts | Lockout risk | Create break-glass accounts |
| Single Conditional Access policy | Gaps in coverage | Layer multiple policies |
| Global Administrator for routine tasks | Excessive privilege | Use least-privilege roles |

---

## Implementation Checklist

### Phase 1: Foundation (Week 1-2)

- [ ] Create and secure emergency access accounts
- [ ] Enable Security Defaults or create baseline Conditional Access policies
- [ ] Block legacy authentication
- [ ] Require MFA for all users
- [ ] Configure password protection

### Phase 2: Privileged Access (Week 3-4)

- [ ] Deploy Privileged Identity Management
- [ ] Convert standing admin access to eligible assignments
- [ ] Configure approval workflows for high-impact roles
- [ ] Set appropriate activation durations
- [ ] Enable PIM alerts

### Phase 3: Advanced Protection (Week 5-6)

- [ ] Deploy risk-based Conditional Access policies
- [ ] Configure Identity Protection
- [ ] Implement device compliance requirements
- [ ] Configure application restrictions

### Phase 4: Governance (Week 7-8)

- [ ] Set up access reviews
- [ ] Configure entitlement management
- [ ] Implement SIEM integration
- [ ] Create monitoring alerts
- [ ] Document policies and procedures

---

## Key Lessons Learned

- Identity security is foundational to cloud security
- MFA alone is not sufficient without context
- Conditional Access is powerful but must be designed carefully
- Privilege management dramatically reduces breach impact
- Monitoring completes the Zero Trust loop
- Emergency access accounts are essential for recovery
- Regular reviews prevent privilege creep

---

## Conclusion

Securing Azure Entra ID is not about enabling every feature — it is about intentional, risk-driven configuration. By applying Zero Trust principles to identity, organizations can significantly reduce the likelihood and impact of account compromise.

This project reinforced the importance of identity as a first-class security concern and demonstrated how native Entra ID capabilities can be used to build a resilient, modern identity security posture.

The configurations in this guide align with:
- Microsoft Zero Trust Architecture
- CIS Microsoft Azure Foundations Benchmark
- CISA Secure Cloud Business Applications (SCuBA) Baselines
- NIST SP 800-63 Digital Identity Guidelines

---

## References

- [Microsoft Zero Trust Architecture](https://learn.microsoft.com/en-us/security/zero-trust/)
- [Azure Entra ID Security Best Practices](https://learn.microsoft.com/en-us/entra/architecture/secure-best-practices)
- [NIST SP 800-63 Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [MITRE ATT&CK – Credential Access Techniques](https://attack.mitre.org/tactics/TA0006/)
- [CISA M365 Security Configuration Baselines](https://www.cisa.gov/resources-tools/services/m365-entra-id)
- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [Microsoft Entra Conditional Access Documentation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/)
- [Privileged Identity Management Documentation](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/)
