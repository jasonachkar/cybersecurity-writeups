# Secure CI/CD Pipelines and Environments

> Status: IN PROGRESS – deep-dive draft

## Executive Summary

Modern CI/CD pipelines are part of the production attack surface: compromising source control, build infrastructure, artifact registries, or deployment systems frequently leads directly to the ability to run arbitrary code in cloud environments. NIST SP 800-204D builds on the Secure Software Development Framework (SSDF) and Executive Order 14028 to define concrete strategies for integrating software supply chain security controls (e.g., SBOM, signing, provenance) into DevSecOps CI/CD pipelines for cloud-native applications.[web:5][web:11][web:32]

This document presents a practitioner-focused threat model for CI/CD pipelines, secure design patterns for identities and environments, and actionable software supply chain controls and operational practices. It is written for senior cloud and security engineers who already understand CI/CD basics and seek deeper guidance on defending pipelines against modern supply chain and infrastructure attacks.

## 1. Pipeline Threat Model

### 1.1 Assets and Trust Boundaries

From an attacker’s perspective, a CI/CD pipeline is a chain of tightly coupled systems and trust boundaries:

- Source control management (SCM): git hosting, merge/pull request workflows, branch protections.
- CI orchestrator: pipeline definitions, workflow engines (e.g., GitHub Actions, GitLab CI, Jenkins), job scheduling.
- Runners/agents: compute instances that execute pipeline jobs, often with access to secrets and cloud credentials.[web:6][web:24]
- Artifact registry: container registries, package repositories, binary stores.
- Deployment systems: infrastructure-as-code engines, release managers, CD systems, or direct cloud APIs.
- Secrets stores and configuration: KMS, secret managers, pipeline variables.[web:6]
- Monitoring and logging: SIEM, cloud-native logging, pipeline audit logs.

Key trust boundaries include:

- Developer workstation → SCM (code and configuration commits).
- SCM → CI orchestrator (webhooks, polling, or integration APIs).
- CI orchestrator → runners (job dispatch and configuration).
- Runners → artifact registry and deployment systems (publishing and rollout).
- Pipeline → cloud environment (deployment credentials).

Breaks in these trust boundaries (e.g., untrusted code flowing into privileged jobs, or runners executing arbitrary commands with cloud-wide permissions) often enable end-to-end compromise of the pipeline and downstream environments.[web:23][web:31]

### 1.2 Attacker Goals and Capabilities

Common attacker goals against CI/CD include:

- Secrets theft: exfiltrating API keys, cloud credentials, signing keys, or database passwords from pipeline config, logs, or runners.[web:6][web:31]
- Artifact tampering: modifying build outputs or images to insert backdoors, cryptominers, or data exfiltration logic.
- Control bypass: disabling or circumventing security gates (tests, scanners, policy checks) to allow vulnerable or malicious code through.
- Deployment hijack: gaining direct ability to deploy arbitrary artifacts into staging or production environments.

Attackers may be:

- External adversaries compromising SCM accounts or exploiting misconfigured SCM/CI integrations.[web:23]
- Supply chain attackers using poisoned dependencies or malicious contributions to introduce exploitable code paths.
- Insiders with privileged access abusing pipelines to push unauthorized changes.

### 1.3 Kill-Chains and Real-World Scenarios

Representative CI/CD kill-chains often follow multi-stage patterns:

1. SCM compromise → malicious change:
   - Attacker steals a maintainer’s credentials or exploits weak MFA on SCM.
   - They introduce a subtle, malicious change to pipeline configuration or application code (e.g., data exfiltration logic or extra pipeline steps).[web:23]
2. Pipeline execution → artifact compromise:
   - CI runs as usual, building and packaging artifacts, but now includes the attacker’s code.
   - If downstream stages lack integrity checks or anomaly detection, the malicious artifact is treated as legitimate.[web:16]
3. Deployment → environment control:
   - CD system deploys the trojaned artifact to staging or production using privileged credentials.
   - The attacker gains footholds in cloud workloads or services and can pivot within the environment.

Another common kill-chain focuses on runners/agents:

1. Runner misconfiguration or exposure:
   - Self-hosted runners are reachable from untrusted networks or share environments across pipelines.
   - Runners reuse workspaces and environment variables without proper isolation or cleanup.[web:6][web:24]
2. Job-level exploitation:
   - Attacker crafts a pipeline definition or contribution that runs arbitrary commands on the runner.
   - Those commands read secrets from environment variables, configuration files, or metadata endpoints and exfiltrate them.[web:31]
3. Direct cloud compromise:
   - Using stolen credentials, the attacker calls cloud APIs directly—bypassing pipelines entirely—to deploy backdoored resources, alter configurations, or access data.

NIST SP 800-204D frames defenses by integrating software supply chain security building blocks (SBOM, signing, provenance, hardened builders) directly into this pipeline, so that even if some components are attacked, the integrity of trusted builds and deployments can still be enforced.[web:5][web:11][web:32]

## 2. Secure CI/CD Design Patterns

### 2.1 Identities and Access for Pipelines

A fundamental design choice is how pipelines authenticate to backing services and cloud APIs:

- Long-lived shared credentials (e.g., static tokens in CI variables) are high-risk: if leaked from logs or runner environments, they enable broad abuse.[web:6][web:31]
- Workload identities and short-lived credentials (e.g., OIDC-based federation from CI to cloud, scoped service accounts) reduce blast radius and limit the value of stolen tokens.[web:18]

Recommended patterns:

- Represent each pipeline or project as a distinct identity with restricted roles (e.g., per-repo service accounts, per-environment deployment roles).
- Use OIDC or cloud-native federation to exchange pipeline identity for short-lived cloud credentials at runtime, rather than storing static keys.[web:18]
- Scope permissions to specific environments and operations (e.g., staging deploy vs production deploy), making lateral movement via pipelines much harder.

### 2.2 Environment and Stage Segregation

Secure CI/CD architectures deliberately separate environments and stages:

- Build and test environments: isolated from production, used for compilation, unit tests, and security scanning.
- Staging/pre-production environments: closer to production, used for integration tests and release validation.
- Production environments: strictly controlled, with limited pipeline entry points and strong guardrails.

Key practices include:

- No direct SCM → production deploy path. All production deployments must originate from approved artifacts in registries, built by trusted pipelines.[web:16]
- Separate runners and agents per environment, avoiding shared infrastructure between build/test and production deployment jobs.
- Strict rules on which pipelines can deploy where—for example, a “release” pipeline that can promote artifacts into production, while feature pipelines cannot.

### 2.3 Hardening Runners and Agents

Runners are often the weakest link in CI/CD security:

- Self-hosted runners may run with excessive OS and network privileges.
- Managed runners can be misused if pipeline definitions allow arbitrary downloads and commands.

Hardening approaches from OWASP and other guidance include:[web:6][web:24][web:31]

- Ephemeral runners per job to minimize residual state and reduce reuse of workspaces across commits or branches.
- Network egress controls to restrict where runners can connect, making exfiltration harder and enabling detection of anomalous destinations.[web:25]
- Carefully scoped access to secrets: mounting only the minimum secrets needed for each job, and avoiding environment-wide secret injection.
- Regular patching and baselining of runner images to reduce exploitability.

### 2.4 Policy Gates and Quality Controls

Security and quality checks must be enforced as gates, not optional steps:

- Static application security testing (SAST) on every change to critical services.
- Dynamic application security testing (DAST) or API fuzzing in pre-production environments.
- Infrastructure-as-code (IaC) scanning to detect misconfigurations and policy violations before deployment.[web:6]
- Container image scanning for vulnerabilities and configuration issues.
- OSS license and dependency policy checks, informed by SBOM data.[web:13]

These gates should be codified as pipeline policies and, where possible, centralized so that common patterns are enforced consistently across many projects—an approach echoed by NIST SP 800-204D and modern CI/CD security best practices.[web:5][web:8][web:28]

## 3. Software Supply Chain Security Controls

### 3.1 SBOM Generation and Lifecycle

Software Bills of Materials (SBOMs) list the components in an application or artifact. In CI/CD, SBOMs should be:

- Generated during build for each artifact, capturing dependencies, versions, and metadata.[web:7][web:13]
- Stored alongside artifacts in registries or artifact stores, and referenced by deployment pipelines.
- Used to power vulnerability management and policy enforcement—for example, flagging high-severity vulnerabilities or disallowed licenses before deployment.[web:13][web:15]

### 3.2 Artifact Signing and Verification

Signing artifacts helps ensure their integrity and authenticity:

- Modern practices emphasize keyless or centralized signing approaches (e.g., Sigstore/cosign) that integrate with CI/CD and avoid complex key management.[web:7][web:17]
- Signatures must be verified at promotion and deployment time; deployments should fail if signatures are missing or do not match expected issuers.

### 3.3 Provenance and SLSA

Software supply chain security frameworks such as SLSA focus on provenance—the who, what, where, and how of a build:[web:7][web:17]

- CI/CD pipelines should produce provenance metadata describing source repositories, builder identities, build parameters, and environments.
- SP 800-204D shows how these building blocks integrate into DevSecOps pipelines to meet SSDF objectives.[web:5][web:11]

### 3.4 Integrating Controls into Pipelines

Practically, CI/CD pipelines can be wired as follows:[web:5][web:7]

- Build stage: compile, run tests, generate SBOM, sign artifacts, and record provenance.
- Registry stage: store artifacts, SBOMs, and provenance documents together.
- Promotion stage: verify signatures, validate provenance, and enforce SBOM-based policies before moving artifacts to staging or production.

## 4. Operational Practices

### 4.1 Monitoring and Detection

Effective monitoring ties together SCM, CI/CD, artifact registries, and cloud environments:[web:16][web:25]

- Collect audit logs from SCM (branch protections, merges), CI (job runs, config changes), runners (command execution), and registries (push/pull events).
- Define detections for unusual pipeline behavior such as sudden changes to workflows, new external dependencies, or anomalous deployment patterns.[web:25][web:28]

### 4.2 Incident Response for Pipeline Compromise

A pipeline compromise playbook typically involves:

- Immediate containment: disable affected pipelines, revoke compromised credentials, freeze suspicious artifacts.[web:16]
- Root cause analysis: identify entry points (SCM, runner, dependency), impacted artifacts and deployments.
- Recovery: rebuild artifacts from known-good source, revalidate signatures and provenance, and restore pipelines with tightened controls.

### 4.3 Feedback Loops and Continuous Improvement

DevSecOps emphasizes continuous improvement:

- Use incidents and near-misses to refine pipeline policies and security gates.
- Regularly reassess SBOM coverage, signing practices, and provenance quality in light of evolving threats and standards.[web:5][web:26]

### 4.4 Security SLOs for CI/CD

Practical security-oriented SLOs may track:

- Percentage of production artifacts with SBOMs and valid signatures.
- Mean time to remediate pipeline-related vulnerabilities and misconfigurations.
- Coverage of pipelines with hardened runners, OIDC-based identities, and enforced security gates.[web:5][web:18]

These SLOs help senior engineers quantify progress toward resilient CI/CD pipelines and align efforts with NIST and industry guidance.
