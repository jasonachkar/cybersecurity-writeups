# Multi-Account Landing Zones and IAM at Scale

> Status: IN PROGRESS – deep-dive draft

## Executive Summary

As organizations scale on AWS, a single account quickly becomes a bottleneck for security, governance, and operations. Multi-account architectures using landing zones—either AWS Control Tower-based or custom—are the industry standard for achieving isolation, blast-radius reduction, and consistent guardrails across teams and workloads. A landing zone is a well-architected, multi-account environment that establishes baseline identity, networking, logging, and policy controls so workloads can be deployed with confidence.[web:115][web:117]

This document describes how senior cloud security engineers can reason about and design multi-account environments, focusing on organizational unit (OU) structures, identity models, and service control policies (SCPs). It treats landing zones as security infrastructure: the goal is not just "more accounts", but clear trust boundaries, least privilege, and enforceable guardrails across dozens or hundreds of accounts.

## 1. Why Multi-Account Architectures Matter

### 1.1 Drivers for Multi-Account Design

Using multiple accounts is a foundational AWS best practice:[web:117][web:122]

- **Isolation and blast radius**: Each account is a strong isolation boundary. Compromise of one account should not automatically expose all workloads or data.
- **Governance and compliance**: Different workloads (e.g., production vs sandbox, regulated vs non-regulated) can be placed in OUs with distinct guardrails and review processes.
- **Billing and quotas**: Accounts provide separate billing views and allow quota management per workload or team.

A landing zone wraps these accounts in a coherent structure with organization-level controls.

### 1.2 Accounts, OUs, and Workloads

Landing zones typically organize accounts into OUs such as:[web:118][web:122]

- **Security** OU: security tooling, log archive, and incident response accounts.
- **Infrastructure / Shared services** OU: networking, identity, and shared platforms.
- **Sandbox / Dev / Test / Prod** OUs: workload accounts with different guardrails and freedoms.

Workloads live in member accounts within these OUs. Policies applied at the OU level (such as SCPs, tag policies, and backup policies) ensure consistent constraints and capabilities.

### 1.3 Landing Zones as Security Baselines

A landing zone is not a one-time project; it is the security and operational baseline for all workloads:[web:115][web:120]

- Centralized logging and monitoring accounts collect events from member accounts.
- Organization-level identities and access patterns provide consistent administrative and break-glass roles.
- SCPs and other policies define which actions and services are allowed or denied across OUs.

Senior engineers treat landing zones as critical security architecture, revisiting them as threats and organizational needs evolve.

## 2. Landing Zone Building Blocks

### 2.1 Core Accounts

Common landing zone patterns use core accounts such as:[web:117][web:122]

- **Management/Org account**: root of AWS Organizations; holds global configuration and high-privilege controls.
- **Log archive** account: receives and retains logs (CloudTrail, Config, application logs) from other accounts.
- **Security tooling** account: hosts SIEM, detection tools, and security automation.

These accounts are deliberately separate from workload accounts, and often have stricter SCPs and break-glass procedures.

### 2.2 Organizational Units and Policy Inheritance

OUs act as containers for accounts and policies:[web:118][web:122]

- Policies attached to an OU apply to all accounts within it, allowing consistent guardrails.
- Hierarchies (e.g., "Sandbox" OU inside broader "Workloads" OU) allow layered policies—broad defaults plus environment-specific restrictions.

Designing OU structures involves balancing clarity (simple hierarchy) with flexibility (room for future workload categories).

### 2.3 Control Tower vs Custom Landing Zones

AWS Control Tower provides a managed way to build landing zones:[web:103][web:122]

- It automates account provisioning, baseline SCPs, and logging/Config setup.
- It is opinionated; customization may require extensions or additional tooling.

Custom landing zones, including Terraform-based implementations, provide more flexibility but require careful design and maintenance.[web:114]

Senior engineers often start with Control Tower for speed, then layer custom controls and IaC around it.

## 3. IAM at Scale

### 3.1 Identity Models for People and Workloads

At scale, identity and access design considers:

- **Human identities**: federated users (e.g., via SSO) mapped to roles for admin, operator, and developer responsibilities.
- **Workload identities**: roles assumed by applications, lambdas, containers, and CI/CD pipelines.
- **Automation identities**: roles used by infrastructure tools and security automation.

The goal is to avoid shared long-lived credentials and rely on roles, federation, and short-lived tokens wherever possible.

### 3.2 Cross-Account Access Patterns

Cross-account access is common in landing zones:

- Roles in target accounts are assumed by identities from central accounts (e.g., security tools querying all accounts).
- Resource-based policies allow specific principals from other accounts to access resources (e.g., shared KMS keys or S3 buckets).

Engineers design these patterns carefully to avoid over-broad trust relationships.

### 3.3 Least Privilege Across Environments

Least privilege is enforced at multiple layers:

- Separate roles for sandbox, dev, test, and prod, each with increasingly strict permissions.
- Scoped policies that limit what resources and services each role can touch.

IAM at scale becomes manageable when combined with SCPs and tag-based conditions, ensuring policies are aligned with OU and environment boundaries.[web:102][web:104]

## 4. Service Control Policies and Guardrails

### 4.1 SCP Strategies

SCPs in AWS Organizations define the maximum permissions available in member accounts:[web:102][web:106]

- **Deny-based** strategies: use explicit denies to block dangerous actions (e.g., disabling logging, using unapproved regions).
- **Allow-based** strategies: define a narrow set of allowed services and actions for highly sensitive OUs.

Designing SCPs requires careful testing to avoid blocking legitimate operations.

### 4.2 Common Guardrail Patterns

Typical SCP guardrails include:[web:104][web:106]

- Preventing root account usage and API keys.
- Enforcing use of specific regions and preventing accidental deployments elsewhere.
- Requiring encryption at rest for storage services.

Tag policies and backup policies ensure consistency of resource metadata and backup configurations.[web:118]

### 4.3 Balancing Safety and Operability

SCPs must be both safe and usable:

- Overly restrictive SCPs can block operational teams from doing necessary work, leading to pressure to weaken controls.
- Iterative design with logging and feedback helps refine SCPs so they target real risks without unnecessary friction.[web:104][web:109]

Senior engineers treat SCPs as code: they version, test, and roll them out carefully.

## 5. Network, Logging, and Detection

### 5.1 Network Segmentation in Multi-Account Setups

Accounts provide coarse-grained segmentation; within them, VPCs and routing define finer boundaries.

Common patterns include:

- Dedicated networking accounts hosting shared VPCs, with workloads attaching via VPC sharing.
- Strict routing rules controlling east-west and north-south traffic.

### 5.2 Centralized Logging and Monitoring

Logging is central to detection and response:[web:107][web:111]

- CloudTrail, Config, and application logs are centralized in log archive accounts.
- Security tooling accounts consume these logs to power detection and investigations.

SCPs and IAM are designed so that logging cannot be disabled or bypassed.

### 5.3 Detection and Response in Landing Zones

Detection strategies leverage the landing zone:

- Monitoring for SCP changes, new account creation, and unusual IAM operations.
- Alerts on cross-account access anomalies.

Response plans consider OU and account boundaries to contain incidents.

## 6. Operational Practices and Case Studies

### 6.1 Typical Failure Modes

Failure modes seen in multi-account environments include:

- Flat OU structures with unclear responsibilities.
- SCPs that either do too little or too much.
- Inconsistent identity and access patterns between accounts.

### 6.2 Example Good Designs

Examples of good landing zone designs illustrate:

- Clear separation of security, shared services, and workloads.
- Well-defined OU structure with layered SCPs.
- IAM and SCPs that reflect least privilege and support detection and response.

These patterns help senior engineers evaluate and improve their own multi-account strategies.
