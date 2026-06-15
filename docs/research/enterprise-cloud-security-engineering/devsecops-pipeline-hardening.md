# 2. DevSecOps & Pipeline Hardening

> The CI/CD pipeline is both the fastest path to production *and* one of the most attractive targets: it holds credentials, builds the artifacts everyone trusts, and pushes directly to runtime. This section covers how to **prevent insecure infrastructure from being provisioned (Policy-as-Code)**, **prove the integrity of what you ship (supply-chain security)**, and **turn scanner noise into prioritized, tracked remediation (vulnerability orchestration)**.

**Contents**
- [2.1 Policy-as-Code (PaC)](#21-policy-as-code-pac)
- [2.2 Supply-chain security & attestation](#22-supply-chain-security--attestation)
- [2.3 Vulnerability orchestration & centralised findings](#23-vulnerability-orchestration--centralised-findings)
- [A reference secure pipeline](#a-reference-secure-pipeline)
- [Best practices summary](#best-practices-summary)
- [Further reading](#further-reading)

---

## 2.1 Policy-as-Code (PaC)

Infrastructure-as-Code (IaC) lets a single misconfiguration replicate across hundreds of resources. **Policy-as-Code** moves compliance checks *left* — into the pull request — so insecure templates are blocked **before** provisioning, deterministically and at scale.

### The tooling landscape

| Tool | Engine / language | Best for | Notes |
|------|-------------------|----------|-------|
| **Checkov** | Python, built-in + custom (Python/YAML) | Terraform, CloudFormation, Bicep, K8s, Dockerfile, ARM | Huge built-in policy set; SARIF output; easy CI integration. |
| **tfsec** | Go (now merged into Trivy) | Terraform | Fast; being consolidated under Trivy. |
| **Terrascan** | Go + OPA/Rego under the hood | Terraform, K8s, Helm | Ships Rego policies; good for OPA shops. |
| **KICS** (Checkmarx) | Go, custom query language | Broad IaC (Terraform, K8s, Ansible, Helm, CFN, Dockerfile) | Very wide coverage. |
| **Trivy** | Go | IaC **and** images, filesystems, SBOM, secrets | One binary for misconfig + vuln + secret scanning. |
| **Regula** | OPA/Rego | Terraform, CloudFormation | Rego-native rules. |
| **OPA + Conftest** | Rego | *Any* structured config (JSON/YAML/HCL/Dockerfile) | General-purpose; write your own org standards. |
| **Gatekeeper / Kyverno** | Rego / Kyverno YAML | Kubernetes **admission control** | Enforces at deploy time, not just CI. |

**Practical guidance:** use an opinionated scanner (Checkov/Trivy) for the long tail of *known* misconfigurations, and **OPA/Rego (Conftest)** for *your organization's* custom standards (e.g., "all storage must use a private endpoint," "only approved VM SKUs"). Version the custom policies in one central repo and consume them everywhere.

### Writing a Rego policy to block insecure Terraform

Goal: **deny any Azure Storage account that allows public blob access or is not behind a private endpoint pattern.** Conftest evaluates Rego against the Terraform plan (in JSON).

```rego
# policy/azure_storage.rego
package main

import future.keywords.in

# Collect storage account resources from a `terraform show -json` plan.
storage_accounts[r] {
    r := input.resource_changes[_]
    r.type == "azurerm_storage_account"
    r.change.actions[_] != "delete"
}

# Rule 1: public network access must be disabled.
deny[msg] {
    sa := storage_accounts[_]
    after := sa.change.after
    after.public_network_access_enabled == true
    msg := sprintf("Storage account '%s' has public_network_access_enabled=true; require private access.", [sa.address])
}

# Rule 2: blobs must not allow anonymous/public access.
deny[msg] {
    sa := storage_accounts[_]
    after := sa.change.after
    after.allow_nested_items_to_be_public == true
    msg := sprintf("Storage account '%s' allows public blob containers; set allow_nested_items_to_be_public=false.", [sa.address])
}

# Rule 3: enforce TLS 1.2 minimum.
deny[msg] {
    sa := storage_accounts[_]
    after := sa.change.after
    after.min_tls_version != "TLS1_2"
    msg := sprintf("Storage account '%s' must set min_tls_version=TLS1_2 (found '%v').", [sa.address, after.min_tls_version])
}
```

Run it in CI:

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
conftest test --policy ./policy tfplan.json
# Non-zero exit on any `deny` -> pipeline fails the PR.
```

> **Why plan-based?** Evaluating the *plan* (resolved values) catches issues that HCL-only scanning misses (variables, modules, computed defaults).

### Admission control: enforce at the cluster, too

CI gates can be bypassed (manual `kubectl apply`, emergency changes). Enforce the same intent at **Kubernetes admission** with **Kyverno** or **Gatekeeper** so the cluster itself rejects non-compliant resources. Example Kyverno policy requiring signed images is shown in §2.2.

### Integrating PaC into the pipeline

- **Run on PR creation** and on every push; comment results inline.
- **Fail on Critical/High**; allow a documented, time-boxed **exception/waiver** process with sign-off (don't let people silently `--soft-fail` everything).
- **Emit SARIF** so results show up in GitHub code scanning / Azure DevOps and flow into your aggregation platform (§2.3).
- **Map findings to owners** via `CODEOWNERS`.
- Combine with **Infracost** to show cost alongside security so platform teams see the full picture.

### Common failure modes

| Failure mode | Consequence | Mitigation |
|--------------|-------------|------------|
| Scanning HCL source only (not the plan) | Misses computed/variable values; false confidence | Scan `terraform show -json` plan output. |
| `--soft-fail` everywhere | Gate becomes advisory theater | Hard-fail on Critical/High; formal waivers only. |
| Policy sprawl / drift | Different repos enforce different rules | Central policy repo, versioned, consumed as a dependency. |
| No exceptions process | Teams disable scanning entirely to ship | Provide a fast, auditable waiver path with expiry. |

---

## 2.2 Supply-chain security & attestation

SolarWinds, Codecov, the `event-stream` and `xz/liblzma` backdoors, and Log4Shell all showed the same lesson: **you inherit the security of everything you build with and ship.** The goal is **verifiable provenance** — being able to prove *what* is in an artifact, *how* it was built, and *that it wasn't tampered with*.

### SLSA — a maturity model for build integrity

**SLSA (Supply-chain Levels for Software Artifacts)** defines escalating guarantees:

| Level | Guarantee (paraphrased) | How you get there |
|-------|-------------------------|-------------------|
| **L1** | Provenance exists | Generate build provenance/metadata. |
| **L2** | Provenance is signed; hosted build service | Use a managed CI with signed provenance. |
| **L3** | Hardened, non-falsifiable provenance; isolated builds | Ephemeral, isolated runners; provenance generated by the platform, not the job. |

Use SLSA as a roadmap: most teams should target **L2→L3** for production artifacts.

### Software Bill of Materials (SBOM)

An SBOM is a machine-readable inventory of every component (and version, and license) in an artifact. Generate it **during the build** and store it **alongside** the artifact.

```bash
# With Syft (CycloneDX JSON)
syft packages dir:. -o cyclonedx-json > sbom.cdx.json

# Or with Trivy (SPDX)
trivy image --format spdx-json -o sbom.spdx.json myregistry.azurecr.io/app:1.4.2
```

Feed the SBOM into vulnerability management (§2.3) and re-scan it continuously — a component that was clean yesterday (e.g., pre-Log4Shell) can become critical overnight without any code change.

### Signing artifacts with Cosign + Sigstore (keyless)

**Cosign** signs container images and arbitrary blobs. **Keyless signing** via **Sigstore** removes long-lived signing keys entirely:

- **Fulcio** issues a short-lived signing certificate bound to your **OIDC identity** (e.g., the GitHub Actions workflow).
- **Rekor** records the signature in a public, tamper-evident **transparency log**.

```yaml
# In a GitHub Actions job (note: id-token: write for keyless OIDC)
permissions:
  id-token: write
  packages: write
steps:
  - uses: sigstore/cosign-installer@v3
  - name: Sign image (keyless)
    env:
      COSIGN_EXPERIMENTAL: "1"
    run: cosign sign --yes "$IMAGE@$DIGEST"
  - name: Attach SBOM as an attestation
    run: cosign attest --yes --predicate sbom.cdx.json --type cyclonedx "$IMAGE@$DIGEST"
```

> Always sign the **digest** (`@sha256:...`), never a mutable tag — tags can be re-pointed.

### Verify at deploy time (don't just sign — enforce)

Signing is worthless if unsigned images can still run. Enforce verification at Kubernetes admission with **Kyverno**:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: Enforce   # reject, don't just audit
  rules:
    - name: verify-cosign-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "myregistry.azurecr.io/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
```

This rejects any image from your registry that wasn't signed by *your* release workflow's identity — closing the loop from §1.1.

### Provenance attestations & build hardening

- Use GitHub's **artifact attestations** / `--provenance` (or the SLSA generator) to record build inputs/outputs (`build-and-attest`).
- **Pin dependencies and actions by digest** (e.g., `actions/checkout@<sha>`), not by mutable tag, to prevent action hijacking.
- Use **ephemeral, isolated runners**; separate build from deploy; restrict runner egress.
- Scan dependencies for **typosquatting** and **dependency-confusion** (private package names that an attacker can publish publicly with a higher version).

### Common failure modes

| Failure mode | Consequence | Mitigation |
|--------------|-------------|------------|
| Signing but not **verifying** | Unsigned/forged images still deploy | Enforce verification at admission (Kyverno/Gatekeeper). |
| Signing a **tag** not a digest | Tag re-pointed to a malicious image post-signing | Sign and deploy by `@sha256` digest. |
| Unpinned CI actions/deps | Action or package hijack injects code | Pin by commit SHA / digest; review updates. |
| SBOM generated once, never re-scanned | New CVEs in existing artifacts go unseen | Continuously re-scan stored SBOMs. |
| Long-lived signing keys in CI | Key theft = forge any artifact | Keyless (Fulcio/Rekor) or HSM-backed keys. |

---

## 2.3 Vulnerability orchestration & centralised findings

Scanning is easy; **acting** on results at scale is the hard part. A mature program produces findings from many sources — SAST (Bandit, Semgrep, CodeQL), DAST (ZAP), SCA (Dependabot, Trivy), IaC (Checkov), secrets (trufflehog), and cloud posture (Defender for Cloud) — and must **deduplicate, prioritize, route, and track** them.

### Aggregate into one system of record (DefectDojo)

**DefectDojo** ingests scanner outputs (SARIF/JSON) and provides products, engagements, deduplication, severity normalization, SLA tracking, and dashboards.

```bash
# Import a scan into DefectDojo via its API (CI step)
curl -s -X POST "$DD_URL/api/v2/import-scan/" \
  -H "Authorization: Token $DD_API_KEY" \
  -F "scan_type=Checkov Scan" \
  -F "engagement=$DD_ENGAGEMENT_ID" \
  -F "minimum_severity=High" \
  -F "active=true" -F "verified=false" \
  -F "file=@checkov.sarif"
```

- **Normalize to SARIF** wherever possible so ingestion is uniform.
- **Deduplicate** across scanners and across runs (DefectDojo hashes findings) so the same CVE in 50 services doesn't create 50 tickets per scan.
- **Map to owners** using labels / `CODEOWNERS` / service catalog.

### Azure Defender for Cloud (cloud posture)

Defender for Cloud continuously assesses resource configurations, produces a **Secure Score**, and surfaces recommendations and regulatory-compliance mappings (NIST, CIS, PCI). Export findings programmatically to **Azure Boards / GitHub Issues** (via the continuous export to Event Hub / Log Analytics, or Logic Apps) so cloud posture flows into the same backlog as code findings.

### Automation workflow (close the loop)

```
scanner (SARIF) ──► normalize ──► DefectDojo (dedupe + severity + SLA)
                                      │
                 new finding ≥ threshold (e.g., Critical/High)
                                      ▼
                          auto-create ticket (Jira/Azure Boards/GH Issue)
                                      │  assign via CODEOWNERS, set due date by SLA
                                      ▼
                  re-scan on next build ──► finding gone? ──► auto-close ticket
```

**Guardrails to avoid alert fatigue:**

- **Threshold gating:** only auto-file tickets at/above a severity (e.g., Critical/High); keep the rest visible in dashboards.
- **Remediation SLOs:** e.g., Critical 7 days, High 30, Medium 90 — and report on breach.
- **Suppress with reason + expiry:** accepted-risk and false-positive states must carry justification and a review date, not be deleted.
- **Trend, don't just count:** track *flow* (new vs. closed) and *aging*, not raw totals.

### Common failure modes

| Failure mode | Consequence | Mitigation |
|--------------|-------------|------------|
| No dedupe | 1 CVE → hundreds of tickets → ignored | Hash-based dedupe in DefectDojo. |
| File a ticket for *everything* | Alert fatigue; real issues buried | Threshold gating + SLO-based prioritization. |
| Findings with no owner | Nobody fixes them | Auto-assign via CODEOWNERS/service catalog. |
| Suppress by deletion | Risk silently reappears / audit gap | Suppress with justification + expiry + review. |

---

## A reference secure pipeline

Putting §2.1–2.3 together with the secretless identity from Section 1:

```yaml
permissions:
  id-token: write     # OIDC for cloud login + keyless signing (no secrets)
  contents: read
  security-events: write   # upload SARIF

jobs:
  secure-build:
    runs-on: ubuntu-latest
    environment: prod
    steps:
      - uses: actions/checkout@<pinned-sha>

      # 1) Policy-as-Code gate on IaC
      - name: IaC scan (Checkov -> SARIF)
        run: checkov -d ./infra -o sarif --output-file-path . --soft-fail-on LOW
      - uses: github/codeql-action/upload-sarif@<pinned-sha>
        with: { sarif_file: results.sarif }

      # 2) Build + SBOM + scan
      - name: Build image
        run: docker build -t "$IMAGE" .
      - name: SBOM
        run: syft "$IMAGE" -o cyclonedx-json > sbom.cdx.json
      - name: Vuln scan (fail on HIGH/CRITICAL)
        run: trivy image --exit-code 1 --severity HIGH,CRITICAL "$IMAGE"

      # 3) Secretless cloud login (federated)
      - uses: azure/login@<pinned-sha>
        with: { client-id: ${{ vars.AZURE_CLIENT_ID }}, tenant-id: ${{ vars.AZURE_TENANT_ID }}, subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }} }

      # 4) Push by digest, sign keyless, attest SBOM
      - name: Push & capture digest
        run: echo "DIGEST=$(docker push "$IMAGE" | awk '/digest:/{print $3}')" >> "$GITHUB_ENV"
      - uses: sigstore/cosign-installer@<pinned-sha>
      - run: cosign sign --yes "$IMAGE@$DIGEST"
      - run: cosign attest --yes --type cyclonedx --predicate sbom.cdx.json "$IMAGE@$DIGEST"

      # 5) Ship findings to the system of record
      - name: Upload to DefectDojo
        run: ./ci/import-to-defectdojo.sh results.sarif
```

Admission control (Kyverno) then verifies the signature at deploy time — so the *only* images that can run in the cluster are the ones this hardened pipeline produced.

---

## Best practices summary

- **Shift PaC left and enforce twice:** scan the Terraform *plan* in CI (hard-fail on Critical/High) **and** enforce at K8s admission.
- **Centralize custom policy** in one versioned Rego/Checkov repo; provide an auditable waiver process.
- **Prove provenance:** generate SBOMs, sign artifacts keyless (Fulcio/Rekor), attest builds, target SLSA L2→L3.
- **Sign digests, verify at admission, pin dependencies** by SHA.
- **Orchestrate, don't drown:** one system of record (DefectDojo), dedupe, threshold-gate tickets, track SLOs, suppress with expiry.
- **Stay secretless:** the pipeline authenticates via OIDC (Section 1), not stored keys.

---

## Further reading

- NIST SSDF SP 800-218, *Secure Software Development Framework* — <https://csrc.nist.gov/pubs/sp/800/218/final>
- NIST SP 800-204D, *Strategies for Integrating Software Supply Chain Security in DevSecOps CI/CD* — <https://csrc.nist.gov/pubs/sp/800/204/d/final>
- SLSA v1.0 specification — <https://slsa.dev/spec/v1.0/>
- Sigstore / Cosign docs — <https://docs.sigstore.dev/>
- OPA / Rego documentation — <https://www.openpolicyagent.org/docs/latest/>
- Conftest — <https://www.conftest.dev/>
- Checkov — <https://www.checkov.io/> · Trivy — <https://trivy.dev/>
- Kyverno — <https://kyverno.io/> · OPA Gatekeeper — <https://open-policy-agent.github.io/gatekeeper/>
- DefectDojo — <https://docs.defectdojo.com/>
- Microsoft Defender for Cloud — <https://learn.microsoft.com/azure/defender-for-cloud/>
- OWASP CycloneDX — <https://cyclonedx.org/> · Anchore Syft — <https://github.com/anchore/syft>

---

[← Previous: IAM](./iam-workload-identity.md) · [Back to overview](./README.md) · [Next: Cloud Security Architecture →](./cloud-security-architecture.md)
