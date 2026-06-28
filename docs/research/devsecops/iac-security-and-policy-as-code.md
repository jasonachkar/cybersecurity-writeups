# IaC Security and Policy-as-Code

> Status: IN PROGRESS – deep-dive draft

## Executive Summary

Infrastructure-as-code (IaC) workflows give engineering teams the ability to change entire environments with a single commit. That power cuts both ways: misconfigurations, embedded secrets, or overly permissive modules can create systemic risk across accounts and regions. Policy-as-code guardrails are the primary way modern cloud and DevSecOps teams keep IaC changes within safe bounds, by enforcing rules automatically in CI/CD pipelines rather than relying on humans to remember them.[web:36][web:40][web:49]

This document presents a threat model for IaC, secure authoring and review practices, practical policy-as-code patterns (with tools such as Open Policy Agent, Conftest, and HashiCorp Sentinel), and continuous drift detection and compliance approaches. It is written for senior engineers who work with Terraform or similar tools and want to integrate IaC and policy controls into secure, scalable DevSecOps workflows.

## 1. IaC Threat Model

### 1.1 Systemic Risk from IaC

IaC amplifies both good and bad decisions:

- A single misconfigured security group or storage bucket pattern can be applied across hundreds of resources and environments.[web:36][web:48]
- Embedded secrets in `.tf` files or variable definitions can leak credentials into version control, state files, and logs.[web:39][web:47]
- Overly permissive IAM roles defined in IaC become the baseline for the environment, making lateral movement easier.

Because IaC is typically executed via CI/CD pipelines with elevated privileges, IaC risks are tightly coupled to pipeline risks: compromise of IaC repositories or plans can lead directly to dangerous infrastructure changes.

### 1.2 Attack Paths via IaC Repositories and Modules

Typical attack patterns include:[web:48][web:50]

- Compromised IaC repository: attacker modifies Terraform or CloudFormation templates to remove encryption, open network paths, or weaken logging.
- Poisoned modules: malicious or vulnerable shared modules introduce insecure defaults or hidden logic into many stacks.
- Registry abuse: unverified module sources or container images referenced from IaC pull code from untrusted registries.

These issues can be hard to spot in manual reviews, especially when IaC is complex and uses many modules and locals. Policy-as-code and automated scanning are necessary to catch systemic issues before they are applied.

### 1.3 Relationship to CI/CD Pipeline Compromise

IaC execution is usually tightly integrated into CI/CD:

- Pipelines run `terraform plan` and `terraform apply` (or equivalents) using privileged credentials.
- The same runners that build application artifacts may also apply infrastructure changes.

A CI/CD compromise can therefore become an IaC compromise:

- An attacker who controls pipelines can inject unauthorized changes into IaC, bypass approvals, or apply plans directly to production.[web:23][web:49]
- Weak segregation between IaC pipelines and application pipelines allows pivoting from one domain to the other.

## 2. Secure IaC Authoring and Review

### 2.1 Modular Design and Least Privilege

Secure IaC starts with design:

- Use modules to encapsulate patterns such as VPCs, security groups, or storage buckets, with secure defaults and limited configuration escape hatches.[web:36][web:39]
- Define IAM roles and policies with least privilege, avoiding wildcards and over-broad permissions; use dedicated roles for IaC execution and runtime workloads.[web:46][web:50]
- Require encryption at rest and in transit as baseline attributes (e.g., encrypted state backends, KMS-integrated storage, TLS-enabled endpoints).[web:42][web:48]

### 2.2 Secrets Management in IaC Workflows

Secrets should never be hardcoded in IaC files:

- Integrate with secret managers such as HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault to retrieve credentials dynamically at runtime.[web:39][web:47][web:49]
- Keep Terraform state files encrypted and stored in secure remote backends (e.g., S3 with KMS, Blob Storage with Key Vault) with access controls and locking to prevent concurrent updates.[web:39][web:42][web:50]
- Use environment variables or secure variable files for sensitive data, and ensure `.tfvars` files containing secrets are not committed to source control.[web:39][web:47]

### 2.3 Change Management and Review for IaC

Reviewing IaC changes requires both process and tooling:

- Enforce pull request workflows with mandatory code review for all IaC changes, especially in shared modules and production stacks.[web:48][web:50]
- Use static analysis tools such as Checkov, tfsec, Terrascan, or cloud provider-specific scanners to detect misconfigurations and policy violations before changes are applied.[web:42][web:44][web:46]
- Combine manual review with policy-as-code checks on plan outputs to catch issues that are difficult to see in raw HCL.

## 3. Policy-as-Code Guardrails

### 3.1 Policy Engines and Plan-Based Evaluation

Policy-as-code moves governance rules out of human memory and into automated engines:[web:37][web:40][web:49]

- Open Policy Agent (OPA) with Conftest allows writing Rego policies that evaluate IaC plans or configuration files.
- HashiCorp Sentinel provides policy enforcement integrated into Terraform Cloud/Enterprise and other HashiCorp products.[web:40][web:49]

A key pattern is to evaluate **plan outputs** rather than raw HCL:

- Terraform plan output (e.g., via `terraform show -json tfplan.binary`) represents resolved resource changes after variables and modules are applied.[web:37]
- Policies inspect the `resource_changes` array to assert facts about the desired state, such as “no public S3 buckets” or “all resources must have required tags.”

### 3.2 Organizational Guardrails and Landing Zones

Policy-as-code should reflect organizational guardrails:

- Landing zones define multi-account or multi-project structures with baseline controls (e.g., mandatory logging, restricted network patterns, centralized security accounts).
- Policies enforce consistent application of these baselines across IaC repositories, failing builds that attempt to bypass guardrails.[web:40][web:48]

Examples include:

- Blocking public S3 buckets or open security groups in production.
- Requiring specific tags (environment, owner, cost center) for all taggable resources.[web:37]
- Restricting certain resource types or regions in sensitive environments.

### 3.3 Integrating Policy Checks into CI/CD Pipelines

To be effective, policy-as-code must run automatically:

- Pipelines generate Terraform plans, convert them to JSON, and run OPA/Conftest or Sentinel policies as a gate before `apply`.[web:37][web:40]
- Failed policy checks block merges or deployments, and policy failures provide actionable messages to developers.
- Centralized policy repositories allow reuse of guardrails across many pipelines and teams.

## 4. Drift Detection and Continuous Compliance

### 4.1 Understanding Drift

IaC promises consistent infrastructure, but reality often diverges:

- Manual changes in cloud consoles or CLI tools introduce configuration drift.
- Emergency fixes applied directly in production may never be backported into code.[web:41][web:43]

Drift can create security gaps, such as:

- Resources that no longer match baseline policies (e.g., unencrypted storage, missing logging).
- IAM changes that grant excessive permissions outside IaC-defined roles.

### 4.2 Drift Detection Approaches

Modern drift detection combines code and runtime views:[web:41][web:43][web:38]

- Periodic scans compare deployed resources against IaC definitions and highlight differences.
- Real-time compliance dashboards ingest IaC definitions, cloud configuration, and policy rules to detect unauthorized changes quickly.
- GitOps-style workflows treat any change outside the IaC pipeline as suspect and either roll back or require explicit approval.

### 4.3 Runtime Guardrails and Automated Remediation

Runtime guardrails complement IaC policies:[web:43]

- Guardrails enforce rules like “no IAM wildcard policies” or “no production changes without a PR” at runtime, not just at deploy time.
- When drift is detected, remediation can roll resources back to baseline code or update IaC to match a verified safe state.

Continuous drift detection tied to guardrails turns compliance from periodic audits into a live system of record.

## 5. Operational Practices and Case Studies

### 5.1 Common Failure Modes in IaC Security

Patterns seen across organizations include:[web:36][web:39][web:48]

- Hardcoded secrets and unencrypted state files.
- Overuse of admin-level IAM roles and wildcards.
- Inconsistent tagging and logging, making it difficult to trace changes.
- Lack of separation between development and production IaC workflows.

### 5.2 Successful Guardrail and Drift Programs

Case studies show successful practices such as:[web:40][web:41][web:43]

- Centralizing policy-as-code and IaC scanning in platform or cloud security teams, with clear ownership and SLAs.
- Providing self-service modules and examples that embed security and compliance, reducing the need for developers to reinvent patterns.
- Combining IaC policy checks, runtime guardrails, and drift detection into a continuous compliance system.

These approaches align closely with modern DevSecOps guidance and help senior engineers build IaC platforms that scale securely across clouds, teams, and workloads.
