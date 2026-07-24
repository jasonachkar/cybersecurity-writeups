# Secure CI/CD boundary and fail-closed gate lab

**Evidence status:** partially tested. The local tests evaluate fixture structure and
fail-closed gate behavior; they do not execute a hosted workflow, authenticate to
Azure, or inspect repository environment settings.

This lab makes CI/CD trust-boundary decisions reproducible. It keeps untrusted pull-
request code away from privileged workflow context, rejects unsafe workflow patterns,
and blocks when scanner evidence is missing, malformed, incomplete, or above policy.

## Prerequisites and run commands

- Node.js 24.12.0 (the tests also support a compatible Node.js 22+ runtime).
- Locked repository dependencies installed with `npm ci --ignore-scripts` for the
  existing YAML/gate suite.

The security-policy suite uses Node.js built-ins only:

```powershell
node labs/secure-cicd/tests/policy-tests.js
```

Run the existing gate and YAML fixture suite after installing locked dependencies:

```powershell
node labs/secure-cicd/tests/run-tests.js
```

Expected output ends with `PASS`. The gate test asserts exit code `0` only for a
completed scanner report within policy. Critical findings and secret findings return
`3`; invalid or failed scanner input returns `2`. A pipeline should treat every
nonzero code as blocking.

## Covered boundaries

| Boundary | Accepted evidence | Rejected evidence |
| --- | --- | --- |
| Immutable dependencies | Every remote action in hardened fixtures uses a full 40-character commit SHA | Mutable major tags such as `actions/cache@v4` |
| Least privilege | Read-only default token and narrowly scoped job permissions | `permissions: write-all` |
| Untrusted PR isolation | Ordinary `pull_request`, no secrets/OIDC/environment, credential-free checkout | `pull_request_target` plus attacker-head checkout and shell execution |
| Artifact integrity | Revision-bound artifact name and `sha256sum --check` before cloud authentication | Privileged execution of an artifact without digest verification |
| Provenance | GitHub attestation creation and `gh attestation verify` before cloud authentication | Privileged artifact use without provenance verification |
| Release approval boundary | Release job binds to the `production` environment | Privileged consumer with no environment binding |
| Cloud authentication | Azure workload federation via job-scoped `id-token: write`; identifiers come from non-secret variables | Stored long-lived cloud credential references |
| Cache isolation | Privileged release consumes no dependency/tool cache | Untrusted producer and privileged consumer share and execute a predictable cache |

The tests deliberately exercise both sides. A negative fixture passing as hardened—or
a hardened fixture matching a prohibited condition—fails the suite.

## Fixtures

- `safe-pr.yml` uses the ordinary `pull_request` event, read-only content permission,
  credential-free checkout, full-SHA action pins, lockfile installation without
  lifecycle scripts, and an environment variable for untrusted PR text.
- `trusted-build-release.workflow.yml` builds only a protected `main` revision,
  records a digest, creates provenance, downloads the revision-bound artifact into a
  separate release job, verifies digest and provenance, binds the job to the
  `production` environment, and only then exchanges GitHub OIDC identity for an Azure
  session. Its final command validates the session and does not deploy resources.
- `unsafe-pr-target.workflow.yaml.txt` combines `pull_request_target`, write-all token,
  mutable action tag, untrusted head checkout, and expression injection into shell.
- `unsafe-privileged-consumer.workflow.yaml.txt` downloads and executes an unverified
  artifact with stored cloud credential references and no protected environment.
- `unsafe-shared-cache.workflow.yaml.txt` lets untrusted code populate a predictable
  cache that a privileged job restores and executes.
- `azure-pipelines.safe.yml` shows a credential-free PR validation stage. A separate
  protected release stage and workload-federated service connection are still
  required for deployment.

Files ending in `.workflow.yaml.txt` are intentionally non-runnable negative fixtures.
The positive GitHub workflow files live outside `.github/workflows`, so repository
validation cannot authenticate or deploy.

## Required platform configuration

The `environment: production` declaration creates a binding, not an approval by
itself. Configure required reviewers, branch/tag restrictions, and environment
secrets/variables in GitHub repository settings. Configure the Azure federated
credential to accept only the intended repository and protected-environment subject,
then grant the resulting identity only the required Azure role. Those settings are
outside this offline lab and require separate review and a non-production exchange
test.

Do not move untrusted artifacts or caches into the release boundary merely because a
later workflow is privileged. Bind an artifact to its producer, repository, revision,
digest, and expected provenance identity; parse reports as data and never execute
untrusted artifact or cache content.

## Failure modes and limitations

The gate validates a small normalized report; production integrations must
authenticate report provenance, bind it to the commit and tool configuration, handle
waivers with expiry/ownership, and preserve evidence. Thresholds are an example, not
an assertion of acceptable organizational risk.

The policy suite is intentionally dependency-free static analysis over controlled
fixtures. It does not replace a general YAML parser or platform policy engine, prove
the safety of pinned third-party actions, verify GitHub/Azure configuration, exercise
environment approval, or validate a real cloud role. GitHub-hosted runner behavior,
artifact service authorization, and attestation verification must be tested in the
target repository before release is enabled.

## Cleanup

The lab creates no persistent resources. It reads fixtures and starts child Node.js
processes only.

## References

- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub workflow event reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [GitHub script injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [GitHub OIDC security hardening for Azure](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-azure)
- [GitHub dependency caching reference](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
