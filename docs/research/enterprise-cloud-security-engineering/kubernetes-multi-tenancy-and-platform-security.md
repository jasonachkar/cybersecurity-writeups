# Kubernetes Multi-Tenancy and Platform Security

> Status: IN PROGRESS – deep-dive draft

## Executive Summary

Sharing Kubernetes clusters across teams and workloads can dramatically improve efficiency, but it also turns the cluster into a shared security boundary. Multi-tenancy introduces risks around isolation, fairness, and noisy neighbors that must be managed through deliberate platform security design. This document presents models for multi-tenancy and the building blocks senior engineers use—namespaces, RBAC, NetworkPolicies, Pod Security controls, quotas, and admission policies—to keep shared clusters safe and predictable.

## 1. Multi-Tenancy Models in Kubernetes

### 1.1 Forms of Multi-Tenancy

Kubernetes supports multiple ways to share clusters:

- Namespaces as tenants: teams or applications are isolated into separate namespaces within a single cluster.
- Dedicated clusters per tenant: each tenant receives its own cluster, with stronger isolation but higher operational cost.
- Hybrid models: a mix of shared clusters for lower-risk workloads and dedicated clusters for highly sensitive workloads.

Choosing a model involves balancing isolation, cost, operational complexity, and the maturity of the platform team.

### 1.2 Trade-Offs and Isolation Levels

Key trade-offs include:

- Security: dedicated clusters provide strong isolation; namespace-based multi-tenancy relies heavily on RBAC, NetworkPolicies, and Pod Security controls.
- Cost and scalability: shared clusters use resources more efficiently, but require sophisticated guardrails.
- Operational overhead: more clusters mean more upgrades, monitoring, and incident response surfaces.

Senior engineers often start with namespace-based multi-tenancy backed by strong guardrails, and selectively introduce dedicated clusters where risk or regulatory requirements demand it.

## 2. Tenant Isolation Building Blocks

### 2.1 Namespace Design and Naming

Namespaces are the primary scoping boundary for many Kubernetes resources:

- Namespaces scope names, RBAC roles and role bindings, quotas, network policies, and Pod Security labels.
- Clear naming conventions (e.g., team-environment, app-tenant) make it easier to reason about ownership and apply policies consistently.

Isolation improves when all per-tenant resources—including RBAC, secrets, and policies—are confined to their namespaces.

### 2.2 RBAC for Tenants and Platform Teams

Role-Based Access Control (RBAC) controls who can do what:

- Tenant roles grant teams the ability to manage their deployments, configmaps, and services within their namespaces.
- Platform roles grant operators the ability to manage cluster-wide resources, policies, and infrastructure.

Design patterns include:

- Using namespace-scoped Roles for day-to-day operations, and ClusterRoles only for platform-level responsibilities.
- Avoiding cluster-admin permissions for tenants; instead, provide narrowly scoped roles for common tasks.

### 2.3 NetworkPolicies for East-West Traffic

NetworkPolicies control traffic between pods and namespaces:

- Default-deny policies block all ingress and egress except explicitly allowed flows.
- Per-namespace policies allow only required traffic (e.g., app → database, ingress → app) and block unnecessary cross-tenant communication.

Well-designed NetworkPolicies prevent tenants from accidentally or deliberately reaching other tenants’ workloads.

## 3. Pod Security and Workload Hardening

### 3.1 Pod Security Standards and Policies

Pod Security Standards (or equivalent policy mechanisms) enforce safe pod configurations:

- Restrict privilege escalation, hostPath mounts, and host networking.
- Control capabilities, user and group IDs, and seccomp profiles.

Tenants should be constrained to baseline or restricted profiles, while only platform components that truly need elevated privileges are granted them.

### 3.2 Admission Controls and Safe Defaults

Admission controllers and policies apply rules as workloads are created:

- Validate manifests against security rules (e.g., no privileged pods, no hostPath, required labels and annotations).
- Mutate manifests to apply safe defaults, such as adding resource requests/limits or security contexts.

By codifying these rules centrally, the platform team can ensure that tenant workloads conform to security expectations without requiring every team to master all details.

## 4. Resource Fairness and Quotas

### 4.1 Quotas and Limits

ResourceQuota and LimitRanges protect the cluster from noisy neighbors:

- Quotas limit total CPU, memory, and object counts per namespace.
- LimitRanges enforce sensible per-container resource requests and limits.

These controls ensure that no single tenant can exhaust cluster capacity or starve others.

### 4.2 Designing for Fairness

Fair resource allocation involves:

- Setting quotas based on tenant needs and adjusting them over time.
- Monitoring usage patterns and revising quotas to prevent both over-allocation and chronic throttling.

Resource controls are part of platform security because they help maintain availability and prevent denial-of-service conditions caused by misbehaving workloads.

## 5. Platform Guardrails and Automation

### 5.1 Policy Engines (OPA, Gatekeeper, Kyverno)

Policy engines allow expressing security and compliance rules as code:

- Rules can require specific labels, block dangerous patterns, and ensure consistency across namespaces.
- Policies run at admission time, preventing non-compliant resources from entering the cluster.

Centralizing these policies gives platform teams a single place to manage cluster-wide guardrails.

### 5.2 CI/CD Integration for Manifest Validation

CI/CD pipelines should validate Kubernetes manifests before they reach the cluster:

- Run policy checks and linters in pipelines to catch issues early.
- Use pre-merge checks so that non-compliant manifests never leave version control.

Aligning pipeline checks with cluster admission policies reduces friction and surprises.

## 6. Operational Practices and Case Studies

### 6.1 Common Failure Modes

Multi-tenant clusters often fail in predictable ways:

- RBAC roles are too broad, granting tenants access beyond their namespaces.
- NetworkPolicies are missing or incomplete, leaving cross-tenant traffic unrestricted.
- Pod Security and admission controls are lax, allowing privileged workloads with risky configurations.

Recognizing these patterns helps engineers audit and improve existing clusters.

### 6.2 Examples of Successful Platform Designs

Successful designs share characteristics such as:

- Clear separation between tenant responsibilities and platform responsibilities.
- Strong namespace isolation, RBAC, NetworkPolicies, and Pod Security standards applied consistently.
- Policy-as-code and CI/CD integration to enforce rules from code to cluster.

These patterns provide a baseline for designing or reviewing multi-tenant Kubernetes platforms that seniors will trust and respect.
