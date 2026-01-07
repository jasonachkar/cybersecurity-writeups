# Privileged Identity Management Configuration Guide

This document provides detailed configuration guidance for implementing Privileged Identity Management (PIM) in Microsoft Entra ID.

## Prerequisites

### Licensing Requirements

- Microsoft Entra ID P2 or Microsoft Entra ID Governance license
- Microsoft Entra Suite (includes PIM capabilities)

### Required Roles

| Task | Required Role |
|------|---------------|
| Configure PIM settings | Privileged Role Administrator or Global Administrator |
| Assign eligible roles | Privileged Role Administrator or Global Administrator |
| Activate roles | User with eligible assignment |
| Approve activations | Designated approvers |

---

## Initial PIM Setup

### Step 1: Access PIM

1. Sign in to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Identity Governance** > **Privileged Identity Management**
3. Select **Microsoft Entra roles** to manage directory roles
4. Select **Azure resources** to manage Azure RBAC roles

### Step 2: Discover Privileged Roles

Before configuring PIM, audit existing privileged assignments:

1. In PIM, select **Microsoft Entra roles** > **Roles**
2. Review each role to identify:
   - Permanent (active) assignments
   - Users who no longer need the role
   - Accounts that should use eligible instead of active

### Step 3: Configure Role Settings

For each role, configure settings before making assignments.

---

## Role Settings Configuration

### Global Administrator Role

| Setting | Value | Rationale |
|---------|-------|-----------|
| Activation maximum duration | 1-2 hours | Shortest practical duration |
| Require MFA on activation | Yes | Always require MFA |
| Require justification | Yes | Document why access is needed |
| Require ticket information | Optional | Integrate with ITSM |
| Require approval | Yes | Require human verification |
| Approvers | Security team members | Not other Global Admins |
| Allow permanent eligible | No | Time-bound only |
| Allow permanent active | No | Except break-glass accounts |
| Notification on activation | All admins | Full visibility |

### Security Administrator Role

| Setting | Value | Rationale |
|---------|-------|-----------|
| Activation maximum duration | 4 hours | Moderate duration |
| Require MFA on activation | Yes | Always require MFA |
| Require justification | Yes | Document why access is needed |
| Require ticket information | No | Not always incident-driven |
| Require approval | Yes | High-impact role |
| Approvers | Privileged Role Admins | Cross-team approval |
| Allow permanent eligible | Yes (time-bound) | 365 days maximum |
| Allow permanent active | No | JIT only |

### Exchange Administrator Role

| Setting | Value | Rationale |
|---------|-------|-----------|
| Activation maximum duration | 8 hours | Longer maintenance windows |
| Require MFA on activation | Yes | Always require MFA |
| Require justification | Yes | Document why access is needed |
| Require ticket information | No | Routine administration |
| Require approval | No | Routine tasks |
| Allow permanent eligible | Yes (time-bound) | 365 days maximum |
| Allow permanent active | No | JIT only |

### User Administrator Role

| Setting | Value | Rationale |
|---------|-------|-----------|
| Activation maximum duration | 8 hours | Support ticket duration |
| Require MFA on activation | Yes | Always require MFA |
| Require justification | Yes | Document why access is needed |
| Require ticket information | No | Routine user management |
| Require approval | No | Routine tasks |
| Allow permanent eligible | Yes (time-bound) | 365 days maximum |
| Allow permanent active | No | JIT only |

---

## PIM for Groups

### When to Use PIM for Groups

PIM for Groups is recommended when:
- Users need access to multiple roles
- Different security policies are needed for different user types
- You want to simplify the activation process
- Managing access for contractors vs. employees

### Creating a PIM-Managed Group

1. Create a new security group (cloud-only)
2. Enable role-assignability if needed for Entra ID roles
3. Navigate to **PIM** > **Groups**
4. Select the group and click **Enable PIM**
5. Configure membership and ownership policies

### Example: Security Team Group

**Scenario:** Security team members need access to multiple security-related roles.

**Group Configuration:**
```
Group Name: PIM-SecurityTeam
Group Type: Security
Membership Type: Assigned
Role-Assignable: Yes (if assigning Entra roles)

Roles Assigned to Group:
- Security Administrator
- Security Reader
- Compliance Administrator
```

**PIM Settings for Group:**
```
Membership Activation:
- Maximum duration: 4 hours
- Require MFA: Yes
- Require justification: Yes
- Require approval: No

Ownership:
- Require approval for owner activation: Yes
- Approvers: Privileged Role Administrators
```

### Example: Different Policies for User Types

**Internal Employee Group:**
```
Group Name: PIM-GlobalAdmins-Internal
Settings:
- Activation duration: 2 hours
- Approval required: No
- MFA required: Yes
```

**External Contractor Group:**
```
Group Name: PIM-GlobalAdmins-External
Settings:
- Activation duration: 1 hour
- Approval required: Yes
- MFA required: Yes
- Notification to all admins: Yes
```

---

## Assignment Process

### Making Eligible Assignments

1. Navigate to **PIM** > **Microsoft Entra roles** > **Roles**
2. Select the role to assign
3. Click **Add assignments**
4. Select assignment type: **Eligible**
5. Select members (users or groups)
6. Configure time bounds:
   - Start date: Immediate or scheduled
   - End date: Time-bound (recommended 365 days or less)
7. Click **Assign**

### Reviewing Existing Assignments

1. Navigate to **PIM** > **Microsoft Entra roles** > **Assignments**
2. Filter by:
   - Eligible assignments
   - Active assignments
   - Expired assignments
3. Identify and remove unnecessary assignments

---

## Activation Process

### User Self-Activation

1. Sign in to [My Access portal](https://myaccess.microsoft.com)
2. Select **Privileged Identity Management**
3. Select **My roles** > **Microsoft Entra roles**
4. Find the role and click **Activate**
5. Complete MFA if required
6. Enter justification
7. Enter ticket number (if required)
8. Submit activation request

### Activation Workflow

```
User Requests Activation
         ↓
    MFA Required? ──Yes──→ Complete MFA
         ↓
    Approval Required? ──Yes──→ Wait for Approval
         ↓
    Role Activated (Time-Limited)
         ↓
    Notification Sent to Admins
         ↓
    Duration Expires → Role Deactivated
```

---

## Approval Workflow

### Configuring Approvers

1. Navigate to **PIM** > **Microsoft Entra roles** > **Roles**
2. Select the role
3. Click **Settings** > **Edit**
4. Enable **Require approval to activate**
5. Select approvers:
   - Individual users
   - Groups
   - Multiple approval levels (if needed)

### Best Practices for Approvers

- Use groups instead of individuals for approver assignments
- Ensure multiple approvers are available for coverage
- Don't assign the same role holders as approvers (separation of duties)
- Configure backup approvers

### Approving Requests

1. Sign in to [My Access portal](https://myaccess.microsoft.com) or check email notification
2. Navigate to **Approve requests**
3. Review request details:
   - Requestor
   - Role requested
   - Justification provided
   - Duration requested
4. Select **Approve** or **Deny**
5. Provide comment (required for denial)

---

## Alerts and Notifications

### Built-In PIM Alerts

| Alert | Trigger | Action |
|-------|---------|--------|
| Roles are being assigned outside of PIM | Direct role assignment | Investigate and remediate |
| Roles don't require MFA for activation | Role settings misconfigured | Enable MFA requirement |
| Too many global administrators | >5 Global Admins | Review and reduce |
| Administrators aren't using their privileged roles | No activation in 90 days | Remove unnecessary assignments |
| Potential stale accounts in a privileged role | Accounts appear unused | Verify and remove if appropriate |

### Configuring Notifications

1. Navigate to **PIM** > **Microsoft Entra roles** > **Roles**
2. Select the role
3. Click **Settings** > **Edit**
4. Configure notification recipients:
   - **Role activation**: Admin, Role, Activating user
   - **Role assignment**: Admin, Role, Assigned user

### Recommended Notification Configuration

For high-impact roles (Global Administrator, Security Administrator):

| Event | Notify Admin | Notify Role | Notify User |
|-------|--------------|-------------|-------------|
| Eligible assignment | Yes | Yes | Yes |
| Active assignment | Yes | Yes | Yes |
| Activation | Yes | Yes | Yes |

---

## Access Reviews Integration

### Creating Access Reviews for PIM Roles

1. Navigate to **Identity Governance** > **Access Reviews**
2. Click **New access review**
3. Configure review:
   - Review type: **Teams + Groups** or **Access packages**
   - For PIM roles, review group membership of PIM-managed groups
4. Set review frequency:
   - Global Admin: Monthly
   - Other privileged roles: Quarterly
5. Assign reviewers:
   - Self-review
   - Manager review
   - Specific reviewer

### Review Actions

| Recommendation | Action |
|----------------|--------|
| User still needs access | Approve |
| User no longer needs access | Deny (remove assignment) |
| Uncertain | Request additional information |

---

## Audit and Compliance

### Accessing PIM Audit Logs

1. Navigate to **PIM** > **Microsoft Entra roles** > **Resource audit**
2. Filter by:
   - Date range
   - Target user
   - Role
   - Operation type

### Key Events to Monitor

| Event | Significance |
|-------|-------------|
| Add member to role (PIM requested) | Normal activation |
| Add member to role outside of PIM | Policy violation - investigate |
| Remove member from role | Access removal - verify authorized |
| Update role setting | Settings change - verify authorized |
| Add eligible member to role | New eligible assignment |

### Exporting Audit Data

For compliance and long-term retention:

1. Configure diagnostic settings for Entra ID
2. Export to:
   - Log Analytics workspace
   - Azure Storage account
   - Event Hub (for SIEM integration)

---

## Troubleshooting

### Common Issues

**User Cannot Activate Role**

1. Verify user has eligible assignment
2. Check if assignment is active (not expired)
3. Verify MFA registration is complete
4. Check Conditional Access policies aren't blocking

**Approval Not Working**

1. Verify approvers are configured
2. Check approvers have access to My Access portal
3. Ensure notifications are being delivered
4. Verify no CA policies blocking approver access

**Notifications Not Received**

1. Check email configuration for recipients
2. Verify notification settings are enabled
3. Check spam/junk folders
4. Confirm email addresses are correct

---

## Migration from Permanent Assignments

### Assessment Phase

1. Export all current permanent role assignments
2. Identify break-glass accounts (keep permanent)
3. Identify service accounts (evaluate for managed identity)
4. Categorize remaining accounts by criticality

### Migration Process

```
For each permanent assignment:
    1. Create eligible assignment for user
    2. Verify user can activate successfully
    3. Remove permanent assignment
    4. Document change
```

### Rollback Plan

If issues occur:
1. Re-assign permanent role temporarily
2. Investigate root cause
3. Address issues
4. Retry migration

---

## Related Documentation

- [README.md](README.md) - Main tutorial
- [conditional-access-policies.md](conditional-access-policies.md) - CA policy reference
- [identity-protection.md](identity-protection.md) - Identity Protection configuration
- [monitoring-alerts.md](monitoring-alerts.md) - Monitoring and alerting
