# Lab reproducibility audit — 2026-11-02

The audit concerns owned local tests. No cloud deployment or production system was
used. Commands below run from repository root after `npm ci --ignore-scripts`.
Every linked lab documents its objective, threat model, architecture, prerequisites,
validation, evidence, cleanup, resource cost and explicit limits. Fixture-only
experiments require their tracked implementation and policy files, not a cloud
resource deployment.

| Lab | Repeatable validation | Evidence boundary |
| --- | --- | --- |
| [Secure CI/CD](../labs/secure-cicd/README.md) | `node labs/secure-cicd/tests/run-tests.js` and `node --test labs/secure-cicd/tests/policy-tests.js` | Local workflow/report models, not hosted execution |
| [IAM/OIDC](../labs/iam-oidc/README.md) | `node labs/iam-oidc/tests/run-tests.js` | 45 structural/policy-model cases, no STS |
| [OAuth/OIDC](../labs/oauth-oidc/README.md) | `node --test labs/oauth-oidc/tests/oauth-security.test.js`; `go -C appsec/scripts/oauth-pkce test ./...` | Local RSA/claim/redirect and S256 checks, no external issuer |
| [AI-agent authorization](../labs/ai-agent-security/README.md) | `node --test labs/ai-agent-security/tests/broker.test.js` | Fake executor and in-memory approval, no real tool action |
| [PostgreSQL RLS](../labs/postgresql-rls/README.md) | `sh labs/postgresql-rls/run-tests.sh` | Real disposable PostgreSQL and pg pool, no managed database |
| [Kubernetes policy](../labs/kubernetes-security/README.md) | `node labs/kubernetes-security/tests/run-tests.js`; `kyverno test labs/kubernetes-security --remove-color` | Native Kyverno CLI (7 existing + 16 new cases), OPA, kubeconform, and a live kind cluster run (83 assertions, not in CI); image evidence model/schema; no live webhook admission |
| [Supply-chain policy](../labs/supply-chain/README.md) | `node labs/supply-chain/tests/run-tests.js` | Digest and authenticated-statement adapter policy; no real signing service |
| [IaC policy](../labs/iac-policy/README.md) | `bash labs/iac-policy/validate-opa.sh`; `npm run verify:terraform` | Native Rego fixture decisions and Terraform schema, no cloud resources |
| [Azure landing zone](../labs/azure-landing-zone/README.md) | `bash labs/azure-landing-zone/validate.sh` | AzureRM 4.50.0 schema and three mocked plan tests, no inheritance/API proof |
| [Event/secret lifecycle](../labs/request-lifecycle/README.md) | `node --test labs/request-lifecycle/lifecycle.test.js` | Six local methods, deterministic cache clock; no provider lease revocation |
| [Docker hardening](../labs/docker-security/README.md) | `node --test labs/docker-security/tests/policy-check.test.js`; `bash labs/docker-security/scripts/run-lab.sh` | 38 static-gate tests (CI); runtime, scan, SBOM and local signing on a disposable Docker host, 85 assertions, not in CI |
| [Linux host telemetry](../labs/linux-host-telemetry/README.md) | `python3 labs/linux-host-telemetry/tests/test_detections.py` | 23 tests on a synthetic corpus plus one strace capture; no production sensor |
| [MCP tool authorization](../labs/mcp-tool-authorization/README.md) | `node --test labs/mcp-tool-authorization/tests/gateway.test.js` | 35 tests and a 16-scenario matrix against a stand-in agent; no model, no identity provider |
| [Tool SSRF](../labs/mcp-tool-ssrf/README.md) | Canonical Compose setup and `test_egress.py` | Six paired HTTP cases, six unit methods and actual isolated TCP-path test |
| [API BOLA](../labs/api-bola-multi-tenant/README.md) | `python3 vulnerability-research/api-bola-multi-tenant/lab/test_api.py` | 14 paired real HTTP cases plus session/role/state checks |
| [CI/CD identity](../labs/cicd-identity-escalation/README.md) | `bash vulnerability-research/cicd-identity-escalation/lab/validate.sh` | Three mock-plan tests and 28 policy/assertion decisions, no cloud exchange |

## Shared verification

`npm run validate` includes every dependency-free/local HTTP suite and research
coverage checks. `npm run verify:native-labs` additionally exercises isolated Docker
services, SQL, native OPA and all Terraform directories. It uses only validation
and mock plans. Kyverno CLI is separately version/checksum verified in the recorded
run; see [verification](../vulnerability-research/verification.md).

Cloud labs stop at compilation, policy evaluation, and documented review plans.
A hypothetical deployment must have separately authorized scope, budget, bootstrap
identity, independent evidence owner and a reviewed teardown plan. No automatic
cloud apply or destroy is part of repository validation.

## Gaps

No real cluster/CNI, cloud identity exchange, external signing envelope, SIEM
collector or production workload was used. PowerShell availability and browser
platform differences are recorded in the verification page. Do not conflate a
missing optional tool with a pass. The local denied/allowed corpus is finite;
representative false-positive rates, TTD/TTC and monthly cost remain not measured.

## References

- [Evidence standards](evidence-standards.md)
- [Article-to-lab claim mapping](research-coverage.json)
