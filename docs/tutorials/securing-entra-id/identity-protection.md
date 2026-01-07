# Identity Protection Configuration Guide

This document provides detailed configuration guidance for Microsoft Entra ID Protection to detect and respond to identity-based risks.

## Overview

Microsoft Entra ID Protection uses machine learning and Microsoft's threat intelligence to:
- Detect suspicious activities and vulnerabilities
- Calculate user and sign-in risk levels
- Automate response to detected risks
- Provide investigation tools and reporting

---

## Prerequisites

### Licensing Requirements

| Feature | License Required |
|---------|------------------|
| Risk detections | Microsoft Entra ID P1 |
| Risk-based Conditional Access | Microsoft Entra ID P2 |
| Full Identity Protection features | Microsoft Entra ID P2 |
| Risky workload identities | Workload Identities Premium |

### Required Roles

| Task | Required Role |
|------|---------------|
| View reports | Security Reader, Global Reader |
| Configure policies | Conditional Access Administrator |
| Remediate risks | Security Operator, Security Administrator |
| Confirm/dismiss risks | Security Administrator |

---

## Risk Detection Types

### User Risk Detections

User risk represents the likelihood that a user account has been compromised. These detections evaluate the user's overall security state.

| Detection | Description | Detection Timing |
|-----------|-------------|------------------|
| Leaked credentials | Credentials found in breached databases | Offline |
| Password spray | Multiple accounts targeted with common passwords | Offline/Real-time |
| Anomalous user activity | Unusual patterns in user behavior | Offline |
| Possible attempt to access Primary Refresh Token | Suspicious PRT access patterns | Offline |
| User reported suspicious activity | User reports unauthorized MFA prompt | Real-time |

### Sign-In Risk Detections

Sign-in risk represents the probability that a specific authentication request is not authorized by the identity owner.

| Detection | Description | Detection Timing |
|-----------|-------------|------------------|
| Anonymous IP address | Sign-in from anonymous proxy/VPN | Real-time |
| Atypical travel | Sign-in from atypical location | Real-time/Offline |
| Malware linked IP address | Sign-in from IP with known malware | Offline |
| Unfamiliar sign-in properties | Sign-in with unusual properties | Real-time |
| Malicious IP address | Sign-in from known malicious IP | Real-time |
| Suspicious inbox manipulation rules | Rules forwarding email externally | Offline |
| Impossible travel | Geographically impossible travel | Real-time/Offline |
| New country | Sign-in from new country for user | Offline |
| Activity from anonymous IP | Activity from TOR exit nodes | Offline |
| Suspicious inbox forwarding | Email forwarding to external address | Offline |
| Anomalous Token | Token with unusual characteristics | Real-time |
| Token issuer anomaly | Token from suspicious issuer | Real-time |
| Mass access to sensitive files | Unusual file access patterns | Offline |

### Risk Levels

| Level | Meaning |
|-------|---------|
| High | High confidence the account is compromised |
| Medium | Some suspicious signals detected |
| Low | Minor anomalies detected |
| None | No risk detected |

---

## Risk Policy Configuration

### User Risk Policy via Conditional Access

Create a Conditional Access policy for user risk remediation.

**Policy: Require Password Change for High-Risk Users**

```
Name: IDP-UserRisk-High-RequirePasswordChange
State: Report-only → On

Assignments:
  Users: All users
  Exclude: Break-glass accounts

Conditions:
  User risk: High

Grant:
  Require password change + Require MFA

Session:
  Sign-in frequency: Every time
```

**Important Considerations:**
- Users must be registered for SSPR (Self-Service Password Reset)
- Hybrid users require password writeback enabled
- Passwordless users will have sessions revoked instead

### Sign-In Risk Policy via Conditional Access

**Policy: Require MFA for Medium/High Sign-In Risk**

```
Name: IDP-SignInRisk-MediumHigh-RequireMFA
State: Report-only → On

Assignments:
  Users: All users
  Exclude: Break-glass accounts

Conditions:
  Sign-in risk: Medium, High

Grant:
  Require authentication strength: Multifactor authentication

Session:
  Sign-in frequency: Every time
```

### Best Practice: Separate Policies

Do not combine user risk and sign-in risk in the same Conditional Access policy. Create separate policies for each risk type.

---

## Named Locations Configuration

Properly configured named locations reduce false positives in risk detections.

### Creating Trusted Locations

1. Navigate to **Entra ID** > **Protection** > **Conditional Access** > **Named locations**
2. Click **+ Countries location** or **+ IP ranges location**

**Corporate Office Location:**
```
Name: Corporate-Office-Primary
Type: IP ranges
Mark as trusted location: Yes
IP ranges:
  - 203.0.113.0/24
  - 198.51.100.0/24
```

**Allowed Countries:**
```
Name: Allowed-Countries
Type: Countries
Mark as trusted location: No
Countries:
  - United States
  - Canada
  - United Kingdom
  (Add based on your organization's locations)
```

---

## Risk Investigation

### Risky Users Report

Navigate to **Entra ID** > **Protection** > **Identity Protection** > **Risky users**

**Information Available:**
- User name and risk level
- Risk state (At risk, Confirmed compromised, Dismissed)
- Last risk update
- Risk detections associated with user

**Investigation Actions:**
1. Review risk detections
2. Check sign-in logs
3. Contact user if needed
4. Confirm or dismiss risk

### Risky Sign-Ins Report

Navigate to **Entra ID** > **Protection** > **Identity Protection** > **Risky sign-ins**

**Information Available:**
- Sign-in details (time, location, app, device)
- Risk level and risk state
- Detections triggered
- Conditional Access policies applied

### Risk Detections Report

Navigate to **Entra ID** > **Protection** > **Identity Protection** > **Risk detections**

**Filtering Options:**
- Date range
- Risk level
- Risk state
- Detection type
- User

---

## Remediation Workflows

### Automatic Remediation

Configure risk-based Conditional Access policies to enable user self-remediation:

| Risk Type | Risk Level | Remediation |
|-----------|------------|-------------|
| Sign-in risk | Medium | MFA challenge |
| Sign-in risk | High | Block or MFA |
| User risk | High | Password change |

### Manual Remediation

For situations requiring admin intervention:

**Dismiss Risk:**
- Use when investigation confirms false positive
- Document reason for dismissal

**Confirm Compromised:**
- Use when investigation confirms actual compromise
- Triggers immediate remediation actions
- Sets user risk to High

**Reset Password:**
- Force password change for user
- Consider also revoking sessions

**Revoke Sessions:**
- Invalidate all active sessions
- User must re-authenticate

### Remediation Process for High-Risk User

```
Detection: User risk elevated to High
    ↓
Investigation:
  1. Review risk detections
  2. Check recent sign-in locations
  3. Verify with user if possible
    ↓
Determination: Compromised or False Positive?
    ↓
If Compromised:
  1. Confirm compromise in portal
  2. Reset password
  3. Revoke all sessions
  4. Review for data exfiltration
  5. Check for persistence mechanisms
    ↓
If False Positive:
  1. Document investigation findings
  2. Dismiss risk
  3. Consider tuning (trusted locations, etc.)
```

---

## Microsoft Authenticator Configuration

### Number Matching

Require users to enter a number displayed during sign-in to prevent MFA fatigue attacks.

1. Navigate to **Entra ID** > **Protection** > **Authentication methods** > **Policies**
2. Select **Microsoft Authenticator**
3. Enable for target users
4. Under **Configure** > **Authentication mode**, select **Any** or **Push**
5. Under **Microsoft Authenticator settings**:
   - Number matching: **Enabled**

### Additional Context

Show users application name and geographic location during approval.

1. In Microsoft Authenticator settings:
   - Show application name: **Enabled**
   - Show geographic location: **Enabled**

---

## Report Suspicious Activity

Enable users to report unauthorized MFA prompts.

1. Navigate to **Entra ID** > **Protection** > **Authentication methods** > **Settings**
2. Enable **Report suspicious activity**
3. Configure response:
   - Mark user at risk: **Yes**
   - Notify security team: **Yes**

When a user reports suspicious activity:
- User risk is elevated to High
- Alert sent to configured recipients
- Appears in risk detections

---

## Workload Identity Protection

For applications and service principals (requires Workload Identities Premium license).

### Risky Workload Identities

Navigate to **Entra ID** > **Protection** > **Identity Protection** > **Risky workload identities**

**Detection Types:**
- Suspicious sign-in activity
- Anomalous service principal activity
- Admin confirmed compromised

### Conditional Access for Workload Identities

```
Name: IDP-WorkloadIdentity-BlockHighRisk
State: Report-only → On

Assignments:
  Workload identities: All service principals
  Exclude: Critical automation accounts

Conditions:
  Service principal risk: High

Grant:
  Block access
```

---

## Integration with Microsoft Defender

### Microsoft Defender for Cloud Apps Integration

1. Navigate to **Microsoft Defender for Cloud Apps** portal
2. Enable anomaly detection policies
3. Configure integration with Identity Protection

**Relevant Alerts:**
- Impossible travel activity
- Activity from infrequent country
- Multiple failed login attempts
- Suspicious inbox manipulation rules

### Microsoft Defender for Identity Integration

For hybrid environments with on-premises Active Directory:

1. Deploy Microsoft Defender for Identity sensors
2. Configure integration with Entra ID
3. Correlate on-premises and cloud identity signals

---

## Monitoring and Reporting

### Identity Secure Score

Navigate to **Entra ID** > **Protection** > **Identity Secure Score**

Track improvement recommendations:
- Require MFA for all users
- Enable password hash sync
- Do not expire passwords
- Enable self-service password reset
- Block legacy authentication

### Weekly Review Checklist

- [ ] Review high-risk users and take action
- [ ] Review high-risk sign-ins
- [ ] Check for new risk detections
- [ ] Verify policies are working as expected
- [ ] Review Identity Secure Score recommendations

### Diagnostic Settings

Configure log export for long-term retention and SIEM integration:

1. Navigate to **Entra ID** > **Diagnostic settings**
2. Add diagnostic setting
3. Select logs to export:
   - RiskyUsers
   - UserRiskEvents
   - RiskyServicePrincipals
   - ServicePrincipalRiskEvents
4. Configure destination:
   - Log Analytics workspace
   - Storage account
   - Event Hub

---

## Troubleshooting

### User Cannot Self-Remediate

1. Verify user is registered for MFA
2. Check SSPR is enabled and user is registered
3. Verify password writeback (hybrid users)
4. Check for conflicting Conditional Access policies

### False Positives

1. Configure trusted named locations
2. Review VPN/proxy configurations
3. Consider excluding specific users or groups
4. Contact Microsoft support for persistent issues

### Risks Not Being Detected

1. Verify Microsoft Entra ID P2 license is assigned
2. Check diagnostic settings are configured
3. Ensure log collection is working
4. Verify no policies are blocking detection signals

---

## Related Documentation

- [README.md](README.md) - Main tutorial
- [conditional-access-policies.md](conditional-access-policies.md) - CA policy reference
- [pim-configuration.md](pim-configuration.md) - PIM setup guide
- [monitoring-alerts.md](monitoring-alerts.md) - Monitoring and alerting
