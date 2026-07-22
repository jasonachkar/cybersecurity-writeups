# Secure CI/CD boundary and fail-closed gate lab

This lab makes two security properties reproducible: untrusted pull-request source is
kept away from privileged workflow context, and a scanner gate blocks when its input
is missing, malformed, incomplete, or above policy.

## Prerequisites and run command

- Node.js 24.12.0 (the tests also support a compatible Node.js 22+ runtime).
- Locked repository dependencies installed with `npm ci --ignore-scripts`.

```powershell
node labs/secure-cicd/tests/run-tests.js
```

Expected output ends with `PASS`. The test asserts exit code `0` only for a completed
scanner report within policy. Critical findings and secret findings return `3`;
invalid or failed scanner input returns `2`. A pipeline should treat every nonzero
code as blocking.

## Fixtures

- `safe-pr.yml` uses the ordinary `pull_request` event, read-only content permission,
  credential-free checkout, full-SHA action pins, lockfile installation without
  lifecycle scripts, and an environment variable for untrusted PR text.
- `unsafe-pr-target.workflow.yaml.txt` is deliberately not an active workflow. It
  demonstrates the dangerous combination of `pull_request_target`, write-all token,
  mutable action tag, untrusted head checkout, and expression injection into shell.
- `azure-pipelines.safe.yml` shows a credential-free PR validation stage. A separate
  protected release stage and service connection are still required for deployment.

## Failure modes and limitations

The gate validates a small normalized report; production integrations must
authenticate report provenance, bind it to the commit and tool configuration, handle
waivers with expiry/ownership, and preserve evidence. Thresholds are an example, not
an assertion of acceptable organizational risk. This lab does not execute GitHub or
Azure DevOps runners and does not prove the safety of third-party actions.

## Cleanup

The lab creates no persistent resources. It reads fixtures and starts child Node.js
processes only.

## References

- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub workflow event reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [GitHub script injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections)
