---
title: "Infrastructure as Code Security and Policy Engineering"
type: "devsecops"
tags:
  - devsecops
  - iac
  - security
  - and
  - policy
date: "2026-07-25"
lastReviewed: "2026-07-25"
readingTime: 12
reviewStatus: "partially-verified"
validatedAgainst:
  - "Terraform S3 backend — https://developer.hashicorp.com/terraform/language/backend/s3"
  - "Terraform state and sensitive data — https://developer.hashicorp.com/terraform/language/state/sensitive-data"
  - "Terraform dependency lock file — https://developer.hashicorp.com/terraform/language/files/dependency-lock"
  - "Terraform saved plan options and security warning — https://developer.hashicorp.com/terraform/cli/commands/plan"
  - "Terraform JSON output format — https://developer.hashicorp.com/terraform/internals/json-format"
  - "OPA policy testing — https://www.openpolicyagent.org/docs/policy-testing"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "partially-tested"
reviewIntervalDays: 90
---

# Infrastructure as Code Security and Policy Engineering

Infrastructure as Code (IaC) is privileged software. Source, modules/providers, state, plans, policy engines, runners, and cloud identities all cross trust boundaries. A scanner is useful, but security comes from controlled dependency resolution, protected state, least-privilege planning/apply identities, independent policy, reviewable changes, drift triage, and runtime verification.

## Threat model and control plane

```
flowchart LR
  C["Reviewed IaC source"] --> D["Locked modules/providers"]
  D --> P["Plan identity"]
  P --> S["Encrypted remote state and lock file"]
  P --> O["Plan artifact: sensitive"]
  O --> G["Policy and human review"]
  G --> A["Separate apply identity"]
  A --> R["Cloud control plane"]
  R --> X["Drift detection and runtime controls"]
```

Threats include malicious modules/providers, credential theft, poisoned runners, state disclosure/tamper, saved-plan substitution, policy bypass, excessive cloud permissions, unreviewed drift, destructive apply, and a scanner failure interpreted as success.

## Backend and state security

State can contain resource identifiers, topology, generated values, and secrets even when outputs are marked sensitive. Treat it as restricted data.

For the Terraform S3 backend, current HashiCorp documentation supports native S3 locking with `use_lockfile = true` and recommends S3 bucket versioning for recovery. DynamoDB-based locking is deprecated and is planned for removal. Existing backends may temporarily configure both during migration, but new guidance should not make a DynamoDB lock table the default.

<div class="language-hcl highlight">

<span id="__span-0-1"><span class="c1">`# Illustrative: values and policy must be organization-specific.`</span>` `</span><span id="__span-0-2"><span class="nb">`terraform`</span><span class="w">` `</span><span class="p">`{`</span>` `</span><span id="__span-0-3"><span class="w">` `</span><span class="kr">`backend`</span><span class="w">` `</span><span class="nv">`"s3"`</span><span class="w">` `</span><span class="p">`{`</span>` `</span><span id="__span-0-4"><span class="w">` `</span><span class="na">`bucket`</span><span class="w">` `</span><span class="o">`=`</span><span class="w">` `</span><span class="s2">`"<restricted-state-bucket>"`</span>` `</span><span id="__span-0-5"><span class="w">` `</span><span class="na">`key`</span><span class="w">` `</span><span class="o">`=`</span><span class="w">` `</span><span class="s2">`"landing-zones/prod/terraform.tfstate"`</span>` `</span><span id="__span-0-6"><span class="w">` `</span><span class="na">`region`</span><span class="w">` `</span><span class="o">`=`</span><span class="w">` `</span><span class="s2">`"ca-central-1"`</span>` `</span><span id="__span-0-7"><span class="w">` `</span><span class="na">`encrypt`</span><span class="w">` `</span><span class="o">`=`</span><span class="w">` `</span><span class="no">`true`</span>` `</span><span id="__span-0-8"><span class="w">` `</span><span class="na">`use_lockfile`</span><span class="w">` `</span><span class="o">`=`</span><span class="w">` `</span><span class="no">`true`</span>` `</span><span id="__span-0-9"><span class="w">` `</span><span class="p">`}`</span>` `</span><span id="__span-0-10"><span class="p">`}`</span>` `</span>

</div>

Enforce TLS, encryption with an appropriately governed KMS key, bucket public-access blocks, versioning, narrow state/lock object permissions, separate state per trust boundary, access logging/audit, retention/recovery, and no developer-wide state download. Backend partial configuration or environment federation avoids committing credentials. `encrypt = true` is not a substitute for bucket/key policies.

OpenTofu and Terraform may diverge in backend, encryption, state, provider, and CLI semantics. Pin the tool and provider/module versions and validate against the chosen implementation; do not assume interchangeable behavior from a shared language.

## Dependency integrity

- Commit dependency lockfiles and use locked initialization in CI.
- Pin registry module/provider versions with reviewed constraints; prefer immutable source revisions for VCS modules.
- Use approved registries/mirrors and protect publishing namespaces.
- Verify provider/plugin checksums through supported lockfile/mirror mechanisms.
- Review transitive module behavior, required provider permissions, and generated resources. A version pin fixes bytes; it does not prove safety.

Do not let untrusted pull-request code run `terraform plan` with a credential that can read production data sources/state or invoke dangerous provider APIs. Use static validation without credentials for untrusted code, then plan a reviewed revision in a protected context.

## Identity separation and plan handling

Planning can call read APIs and data sources, and some providers have surprising side effects. Use a narrow plan identity and an even more carefully scoped apply identity where practical. Prefer OIDC/workload federation to stored cloud keys.

Saved binary plan files can contain sensitive cleartext values and encode actions for a particular state/configuration/provider set. Encrypt/restrict/expire them as artifacts, bind them to source commit, state lineage/version, lockfile, tool version, policy evidence, and approval, then apply that exact plan. Do not accept a plan from an untrusted workflow.

Separate production environments/accounts/subscriptions, protected approvals, and apply roles. Restrict bypass paths such as direct owner access, alternate pipelines, local apply, state editing, policy exemption, or deployment through a different tool.

## Policy as code

Use complementary checks:

- syntax/format/validation;
- static misconfiguration and secret scanning;
- plan-aware policy evaluating the actual proposed graph;
- organization/cloud policy at the control plane;
- runtime configuration and threat detection after apply.

Policy results need tool/configuration version, input identity, completion state, severity/rule, resource address, owner, waiver, and expiry. Missing/invalid plan or scanner output blocks. Roll out new rules in observation mode, triage false positives, then enforce with owned exceptions. Test both violating and compliant fixtures.

Guardrails should cover public exposure, identity/role scope, encryption and key governance, logging, network paths, backup/recovery, metadata-service protections, regions, tags/ownership, managed service configurations, and destructive lifecycle behavior according to risk. Avoid counting policies as equivalent controls without testing their actual provider semantics.

## Reproducible local evidence

The [Terraform plan and Rego policy lab](../labs/iac-policy/README.md) is **partially tested**. It separates three offline checks:

1. dependency-free Node.js assertions over backend text, policy text, and serialized plan fixtures;
2. OPA `1.17.0` Rego v1 unit tests over four reviewed plan JSON inputs; and
3. Terraform `1.14.6` formatting plus `init -backend=false` and `validate` for deliberately insecure and hardened backend examples.

From the repository root, the tested commands are:

<div class="language-powershell highlight">

<span id="__span-1-1"><span class="n">`node`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`tests`</span><span class="p">`/`</span><span class="n">`run-tests`</span><span class="p">`.`</span><span class="n">`js`</span>` `</span><span id="__span-1-2">` `</span><span id="__span-1-3"><span class="n">`opa`</span>` `<span class="n">`test`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`policy`</span><span class="p">`/`</span><span class="n">`terraform`</span><span class="p">`.`</span><span class="n">`rego`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`policy`</span><span class="p">`/`</span><span class="n">`secure_fixture_test`</span><span class="p">`.`</span><span class="n">`rego`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`fixtures`</span><span class="p">`/`</span><span class="n">`secure_plan`</span><span class="p">`.`</span><span class="n">`json`</span>` `<span class="n">`-v`</span>` `</span><span id="__span-1-4"><span class="n">`opa`</span>` `<span class="n">`test`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`policy`</span><span class="p">`/`</span><span class="n">`terraform`</span><span class="p">`.`</span><span class="n">`rego`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`policy`</span><span class="p">`/`</span><span class="n">`insecure_fixture_test`</span><span class="p">`.`</span><span class="n">`rego`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`fixtures`</span><span class="p">`/`</span><span class="n">`insecure_plan`</span><span class="p">`.`</span><span class="n">`json`</span>` `<span class="n">`-v`</span>` `</span><span id="__span-1-5"><span class="n">`opa`</span>` `<span class="n">`test`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`policy`</span><span class="p">`/`</span><span class="n">`terraform`</span><span class="p">`.`</span><span class="n">`rego`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`policy`</span><span class="p">`/`</span><span class="n">`unknown_fixture_test`</span><span class="p">`.`</span><span class="n">`rego`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`fixtures`</span><span class="p">`/`</span><span class="n">`unknown_plan`</span><span class="p">`.`</span><span class="n">`json`</span>` `<span class="n">`-v`</span>` `</span><span id="__span-1-6"><span class="n">`opa`</span>` `<span class="n">`test`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`policy`</span><span class="p">`/`</span><span class="n">`terraform`</span><span class="p">`.`</span><span class="n">`rego`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`policy`</span><span class="p">`/`</span><span class="n">`deleted_fixture_test`</span><span class="p">`.`</span><span class="n">`rego`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`fixtures`</span><span class="p">`/`</span><span class="n">`deleted_control_plan`</span><span class="p">`.`</span><span class="n">`json`</span>` `<span class="n">`-v`</span>` `</span><span id="__span-1-7">` `</span><span id="__span-1-8"><span class="n">`terraform`</span>` `<span class="n">`fmt`</span>` `<span class="n">`-check`</span>` `<span class="n">`-recursive`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`terraform`</span>` `</span><span id="__span-1-9"><span class="n">`terraform`</span>` `<span class="n">`-chdir`</span><span class="p">`=`</span><span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`terraform`</span><span class="p">`/`</span><span class="n">`insecure`</span>` `<span class="n">`init`</span>` `<span class="n">`-backend`</span><span class="p">`=`</span><span class="n">`false`</span>` `<span class="n">`-input`</span><span class="p">`=`</span><span class="n">`false`</span>` `</span><span id="__span-1-10"><span class="n">`terraform`</span>` `<span class="n">`-chdir`</span><span class="p">`=`</span><span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`terraform`</span><span class="p">`/`</span><span class="n">`insecure`</span>` `<span class="n">`validate`</span>` `</span><span id="__span-1-11"><span class="n">`terraform`</span>` `<span class="n">`-chdir`</span><span class="p">`=`</span><span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`terraform`</span><span class="p">`/`</span><span class="n">`hardened`</span>` `<span class="n">`init`</span>` `<span class="n">`-backend`</span><span class="p">`=`</span><span class="n">`false`</span>` `<span class="n">`-input`</span><span class="p">`=`</span><span class="n">`false`</span>` `</span><span id="__span-1-12"><span class="n">`terraform`</span>` `<span class="n">`-chdir`</span><span class="p">`=`</span><span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iac-policy`</span><span class="p">`/`</span><span class="n">`terraform`</span><span class="p">`/`</span><span class="n">`hardened`</span>` `<span class="n">`validate`</span>` `</span>

</div>

On 2026-07-23, the structural harness ended with `PASS`; all five OPA assertions passed across the four invocations; and both Terraform configurations initialized offline and validated successfully. `-backend=false` prevented backend initialization, and the configurations declare no provider/resource operations. No AWS API, remote state, plan, or apply was used.

The secure plan fixture is accepted. Negative fixtures require findings for:

- a public S3 ACL and missing public-access block, encryption, or access logging;
- public security-group ingress;
- a publicly accessible or unencrypted database;
- an IAM statement with wildcard action and resource;
- missing `Environment`/`Owner` tags used by this example policy;
- security-relevant database values that are unknown at evaluation time; and
- deletion of a modeled public-access/encryption/logging control.

The unknown-value fixture fails closed by design. You can choose to defer the decision instead, but whatever check comes later still has to block until the value is actually known. Plan JSON `format_version: "1.2"` is a fixture contract, not a promise that all future Terraform output will retain that version or shape.

## Drift response

Drift is a signal, not authorization to run `terraform apply` automatically. An automatic apply can delete an emergency control, overwrite incident containment, recreate a compromised configuration, or make an unreviewed destructive change.

Classify drift:

1. determine actor, time, affected resource, incident/change context, and intended source of truth;
2. assess exposure, destructive actions, data-plane effects, and dependencies;
3. decide whether to import/update code, revert runtime, preserve emergency change, or investigate as an incident;
4. generate a fresh reviewed plan with the correct identity and state lock;
5. apply through the normal protected promotion path;
6. verify runtime and record resolution.

Emergency console changes need a reconciliation workflow, not concealment.

## Failure modes and recovery

- **Lock acquisition failure:** investigate active operation and stale lock. Do not force-unlock until ownership is known and no operation is active.
- **State corruption/deletion:** stop applies, preserve evidence, recover a reviewed version, validate lineage/serial/resources, and plan before changes.
- **Backend/KMS outage:** do not fall back to local unprotected state.
- **Partial apply:** capture logs/state, inspect actual resources, and create a new recovery plan; do not rerun blindly.
- **Policy/scanner outage:** block or use explicit time-bounded risk acceptance; no empty success.
- **Compromised provider/module/runner:** revoke sessions, quarantine outputs/plans, restore trusted dependencies/runner, inspect control-plane audit, and re-plan.
- **Unexpected destructive plan:** stop, validate variables/workspace/state/source, require specialized approval, and rehearse recovery for stateful resources.

## Deployment and rollback

Canary guardrails and modules in non-production. Use small plans, dependency-aware ordering, maintenance windows where required, and pre-change backup/recovery evidence. Terraform rollback is a new forward plan; not every cloud operation is reversible. Deletion, key rotation, database migration, network cutover, and policy inheritance need resource-specific recovery procedures.

## Validation checklist

Tool, provider, module, and lockfile versions are controlled.

Remote state uses encryption, TLS, versioning, least privilege, audit, and native locking supported by the selected tool.

Untrusted PR validation has no production state/cloud credential.

Plan and apply identities, artifacts, approvals, and environments are separated.

Policy/scanner failures block; waivers are narrow, owned, and expiring.

Destructive and high-blast-radius changes receive specialized review.

Drift is investigated and approved, never blindly auto-applied.

Runtime evidence and state recovery are tested.

## Limitations

The backend examples are not deployable baselines. They omit organization-specific bucket creation, public-access block, versioning, logging, KMS key/resource policy, replication, network, identity, retention, and disaster-recovery controls. Terraform offline validation checks syntax and internal consistency only; it does not establish backend reachability, permissions, locking behavior, provider semantics, or cloud runtime state.

The Rego policy intentionally supports a small set of AWS resource shapes from reviewed fixtures. It is not a complete control catalog, a general Terraform JSON validator, or evidence that an independently generated plan is authentic and bound to the reviewed commit. OPA evaluation does not replace SCPs/cloud policy, configuration monitoring, or drift investigation. OpenTofu was not executed by this lab.

## References

- [Terraform S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3)
- [Terraform state and sensitive data](https://developer.hashicorp.com/terraform/language/state/sensitive-data)
- [Terraform dependency lock file](https://developer.hashicorp.com/terraform/language/files/dependency-lock)
- [Terraform saved plan options and security warning](https://developer.hashicorp.com/terraform/cli/commands/plan)
- [Terraform JSON output format](https://developer.hashicorp.com/terraform/internals/json-format)
- [OPA policy testing](https://www.openpolicyagent.org/docs/policy-testing)
- [OpenTofu S3 backend](https://opentofu.org/docs/language/settings/backends/s3/)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
