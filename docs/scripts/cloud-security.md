# Cloud Security Automation Scripts

This section showcases custom security tools and policy analysis scripts written in Go. These scripts can run in standalone CLI environments or integrate into cloud threat detection pipelines.

---

## 1. SCP Conflict Auditor (`scp-auditor.go`)

### Purpose
Validates and simulates AWS Service Control Policy (SCP) evaluation logic across nested Organizational Units (OUs) to detect policy conflicts, redundant allows, or unintended blocks before they are pushed to AWS Organizations.

### Code Implementation
```go
--8<-- "cloud-security/scripts/scp-auditor.go"
```

---

## 2. IAM Policy Analyzer (`iam-analyzer.go`)

### Purpose
Scans simulated or provided AWS IAM policy documents (in JSON format) for over-permissive configurations, wildcards, and administrative privilege escalation paths.

### Code Implementation
```go
--8<-- "cloud-security/scripts/iam-analyzer.go"
```

---

## 3. Kubernetes RBAC Auditor (`k8s-rbac-auditor.go`)

### Purpose
Scans Kubernetes RBAC (Roles and ClusterRoles) configurations for high-risk permissions, wildcard verbs, and administrative escalation vectors (such as `bind` or `escalate` privileges).

### Code Implementation
```go
--8<-- "cloud-security/scripts/k8s-rbac-auditor.go"
```
