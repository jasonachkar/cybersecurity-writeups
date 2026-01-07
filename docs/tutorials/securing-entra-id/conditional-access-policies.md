# Conditional Access Policy Reference

This document provides detailed configuration guidance for implementing Conditional Access policies in Microsoft Entra ID.

## Policy Naming Convention

Use a consistent naming convention for all policies:

```
[Priority]-[Category]-[Target]-[Action]

Examples:
- 001-Foundation-AllUsers-RequireMFA
- 002-Foundation-AllUsers-BlockLegacyAuth
- 010-ZeroTrust-Admins-RequirePhishingResistantMFA
- 020-RemoteWork-AllUsers-RequireCompliantDevice
```

---

## Secure Foundations Policies

### Policy 1: Require MFA for All Users

**Purpose:** Ensure all users authenticate with MFA

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 001-Foundation-AllUsers-RequireMFA |
| State | Report-only → On |
| Users | All users |
| Exclude | Break-glass accounts, Directory sync accounts |
| Cloud apps | All cloud apps |
| Conditions | None |
| Grant | Require authentication strength: Multifactor authentication |
| Session | None |

**JSON Export:**
```json
{
  "displayName": "001-Foundation-AllUsers-RequireMFA",
  "state": "enabledForReportingButNotEnforced",
  "conditions": {
    "users": {
      "includeUsers": ["All"],
      "excludeGroups": ["BreakGlassAccounts", "DirectorySyncAccounts"]
    },
    "applications": {
      "includeApplications": ["All"]
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": [],
    "authenticationStrength": {
      "id": "00000000-0000-0000-0000-000000000002"
    }
  }
}
```

---

### Policy 2: Block Legacy Authentication

**Purpose:** Prevent authentication using legacy protocols that bypass MFA

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 002-Foundation-AllUsers-BlockLegacyAuth |
| State | Report-only → On |
| Users | All users |
| Exclude | None (apply to all including break-glass) |
| Cloud apps | All cloud apps |
| Conditions | Client apps: Exchange ActiveSync clients, Other clients |
| Grant | Block access |
| Session | None |

**Important:** This policy should NOT exclude break-glass accounts. Legacy authentication should never be allowed.

---

### Policy 3: Require MFA for Azure Management

**Purpose:** Protect Azure portal and Azure Resource Manager access

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 003-Foundation-AllUsers-RequireMFAAzureManagement |
| State | Report-only → On |
| Users | All users |
| Exclude | Break-glass accounts |
| Cloud apps | Microsoft Azure Management |
| Conditions | None |
| Grant | Require authentication strength: Multifactor authentication |
| Session | Sign-in frequency: Every time |

---

### Policy 4: Require Device Compliance or Hybrid Join

**Purpose:** Ensure access only from managed devices

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 004-Foundation-AllUsers-RequireCompliantDevice |
| State | Report-only → On |
| Users | All users |
| Exclude | Break-glass accounts, Guest users |
| Cloud apps | All cloud apps |
| Conditions | Device platforms: Windows, macOS |
| Grant | Require one of: Compliant device, Hybrid Azure AD joined device |
| Session | None |

---

## Zero Trust Policies

### Policy 5: Require Phishing-Resistant MFA for Admins

**Purpose:** Protect administrative accounts with strongest authentication

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 010-ZeroTrust-Admins-RequirePhishingResistantMFA |
| State | Report-only → On |
| Users | Directory roles (see list below) |
| Exclude | Break-glass accounts |
| Cloud apps | All cloud apps |
| Conditions | None |
| Grant | Require authentication strength: Phishing-resistant MFA |
| Session | Sign-in frequency: Every time |

**Target Roles:**
- Global Administrator
- Security Administrator
- Privileged Role Administrator
- Conditional Access Administrator
- Exchange Administrator
- SharePoint Administrator
- User Administrator
- Billing Administrator
- Application Administrator
- Cloud Application Administrator

---

### Policy 6: Block High-Risk Sign-Ins

**Purpose:** Block authentication attempts with high risk scores

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 011-ZeroTrust-AllUsers-BlockHighRiskSignIn |
| State | Report-only → On |
| Users | All users |
| Exclude | Break-glass accounts |
| Cloud apps | All cloud apps |
| Conditions | Sign-in risk: High |
| Grant | Block access |
| Session | None |

---

### Policy 7: Require MFA for Medium-Risk Sign-Ins

**Purpose:** Challenge suspicious sign-ins with MFA

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 012-ZeroTrust-AllUsers-MFAMediumRiskSignIn |
| State | Report-only → On |
| Users | All users |
| Exclude | Break-glass accounts |
| Cloud apps | All cloud apps |
| Conditions | Sign-in risk: Medium |
| Grant | Require authentication strength: Multifactor authentication |
| Session | Sign-in frequency: Every time |

---

### Policy 8: Require Password Change for High-Risk Users

**Purpose:** Force credential reset for likely compromised accounts

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 013-ZeroTrust-AllUsers-PasswordChangeHighRiskUser |
| State | Report-only → On |
| Users | All users |
| Exclude | Break-glass accounts |
| Cloud apps | All cloud apps |
| Conditions | User risk: High |
| Grant | Require password change + Require MFA |
| Session | None |

**Prerequisites:**
- Self-Service Password Reset (SSPR) enabled
- Password writeback enabled (for hybrid users)
- Users registered for MFA

---

## Remote Work Policies

### Policy 9: Require Approved Apps on Mobile

**Purpose:** Restrict mobile access to approved applications

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 020-RemoteWork-AllUsers-ApprovedMobileApps |
| State | Report-only → On |
| Users | All users |
| Exclude | Break-glass accounts |
| Cloud apps | Office 365 |
| Conditions | Device platforms: iOS, Android |
| Grant | Require approved client app |
| Session | None |

---

### Policy 10: Require App Protection Policy on Mobile

**Purpose:** Ensure data protection on mobile devices

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 021-RemoteWork-AllUsers-AppProtectionPolicy |
| State | Report-only → On |
| Users | All users |
| Exclude | Break-glass accounts |
| Cloud apps | Office 365 |
| Conditions | Device platforms: iOS, Android |
| Grant | Require app protection policy |
| Session | None |

---

## Administrator Protection Policies

### Policy 11: Block Admin Access from Untrusted Countries

**Purpose:** Geo-restrict administrative access

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 030-AdminProtect-Admins-BlockUntrustedCountries |
| State | Report-only → On |
| Users | Directory roles (all admin roles) |
| Exclude | Break-glass accounts |
| Cloud apps | All cloud apps |
| Conditions | Locations: All locations EXCEPT allowed countries |
| Grant | Block access |
| Session | None |

**Allowed Countries List:** Configure based on your organization's operational locations.

---

### Policy 12: Require Compliant Device for Admins

**Purpose:** Ensure admin access only from managed devices

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 031-AdminProtect-Admins-RequireCompliantDevice |
| State | Report-only → On |
| Users | Directory roles (all admin roles) |
| Exclude | Break-glass accounts |
| Cloud apps | All cloud apps |
| Conditions | None |
| Grant | Require compliant device |
| Session | None |

---

## Session Control Policies

### Policy 13: Limit Session Duration for Sensitive Apps

**Purpose:** Reduce session duration for high-value applications

**Configuration:**

| Setting | Value |
|---------|-------|
| Name | 040-Session-AllUsers-SensitiveAppSessionLimit |
| State | Report-only → On |
| Users | All users |
| Exclude | Break-glass accounts |
| Cloud apps | Azure Portal, Microsoft 365 Admin Center |
| Conditions | None |
| Grant | Require MFA |
| Session | Sign-in frequency: 4 hours |

---

## Policy Deployment Checklist

### Phase 1: Report-Only Mode
- [ ] Deploy all policies in report-only mode
- [ ] Monitor sign-in logs for 1-2 weeks
- [ ] Review "What If" results
- [ ] Identify users who would be blocked
- [ ] Adjust exclusions as needed

### Phase 2: Limited Enforcement
- [ ] Enable policies for pilot group
- [ ] Monitor for issues for 1 week
- [ ] Gather user feedback
- [ ] Address any access problems

### Phase 3: Full Enforcement
- [ ] Enable policies for all users
- [ ] Monitor sign-in logs daily
- [ ] Have support team ready for issues
- [ ] Document any exceptions

---

## Troubleshooting Common Issues

### Users Blocked Unexpectedly

1. Check Sign-in logs for failure reason
2. Use "What If" tool to identify triggering policy
3. Verify user is not using legacy authentication
4. Check device compliance status
5. Review risk detections in Identity Protection

### MFA Prompt Loop

1. Verify user has registered MFA methods
2. Check for conflicting policies
3. Ensure session controls are consistent
4. Check for browser cookie issues

### Service Account Blocked

1. Use managed identities instead of service accounts
2. If service accounts required, exclude from CA policies targeting users
3. Use Conditional Access for Workload Identities for service principals

---

## Related Documentation

- [README.md](README.md) - Main tutorial
- [pim-configuration.md](pim-configuration.md) - PIM setup guide
- [identity-protection.md](identity-protection.md) - Identity Protection configuration
- [monitoring-alerts.md](monitoring-alerts.md) - Monitoring and alerting
