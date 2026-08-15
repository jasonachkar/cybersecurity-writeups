---
title: "SecureObs: Customer-side CI Security Scanning with a Multi-tenant Findings Platform"
id: "secureobs-multitenant-security-scanner"
navTitle: "SecureObs architecture"
order: 50
type: "devsecops"
tags:
  - devsecops
  - secureobs
  - multitenant
  - security
  - scanner
date: "2026-07-25"
lastReviewed: "2026-07-25"
reviewStatus: "partially-verified"
validatedAgainst:
  - "PostgreSQL row security policies — https://www.postgresql.org/docs/current/ddl-rowsecurity.html"
  - "GitHub secure use reference — https://docs.github.com/en/actions/reference/security/secure-use"
  - "Azure Pipelines security guidance — https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview"
  - "NIST Secure Software Development Framework — https://csrc.nist.gov/pubs/sp/800/218/final"
  - "OWASP ASVS project — https://owasp.org/www-project-application-security-verification-standard/"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "partially-tested"
reviewIntervalDays: 90
---

# SecureObs: Customer-side CI Security Scanning with a Multi-tenant Findings Platform

> **A note on scope:** everything under **Implemented today** is what I can personally confirm about SecureObs, as of 2026-07-21. This public repo doesn't include the private SecureObs source, deployment records, customer data, or its commit history. Where I've reproduced a control here for demonstration, I've labeled it **reproduced**; recommendations are labeled **recommended**; anything I'm just considering for later lives under **Future control-plane architecture under consideration**.

SecureObs does not currently pull customer repositories into a server-side worker fleet. Its scanner container runs inside the customer's GitHub Actions or Azure DevOps pipeline. That placement keeps source checkout and scanner execution in the customer's CI boundary while SecureObs provides scanner configuration, multitenant findings ingestion, deduplication, dashboard access, and a build-gate decision.

## The core decision

Treat the current product as two cooperating security boundaries:

1. **Customer-side execution plane:** the customer pipeline starts the SecureObs scanner image, retrieves the enabled-scanner configuration, executes seven bundled scanners locally, normalizes their findings, uploads them, and calls the build gate.
2. **SecureObs findings plane:** the .NET API authenticates and authorizes requests, stores tenant-scoped data in PostgreSQL with application authorization and `FORCE ROW LEVEL SECURITY`, deduplicates findings, serves the Angular dashboard, and returns the gate decision.

Do not describe SecureObs as operating a central scan queue, ephemeral scanner workers, a credential broker, immutable server-side job envelopes, or independent policy-evaluation workers today. Those are possible future designs, not current production architecture.

## Evidence classification

| Statement | Classification |
|----|----|
| Angular 21 dashboard, .NET 8 API, PostgreSQL application authorization plus forced RLS | **Owner-confirmed current implementation, as of 2026-07-21** |
| Scanner image runs in customer GitHub Actions or Azure DevOps pipelines | **Owner-confirmed current implementation, as of 2026-07-21** |
| Scanner retrieves enabled-scanner configuration, runs seven bundled scanners locally, normalizes and uploads findings, then calls the build gate | **Owner-confirmed current implementation, as of 2026-07-21** |
| Findings ingestion, normalization, deduplication, build gating, GitHub Actions integration, and Azure DevOps integration exist | **Owner-confirmed current implementation, as of 2026-07-21** |
| Repository gate rejects failed/malformed reports and above-policy findings | **Reproduced** in `labs/secure-cicd`; not proof of identical private code |
| Repository RLS lab rejects cross-tenant access, invalid context, pooled-session leakage, and bypass-role drift | **Reproduced** in `labs/postgresql-rls`; not proof of identical private schema |
| A named historical SecureObs defect, incident, customer impact, or remediation date occurred | **Not claimed** unless I have an issue, commit, test, or incident record to point to |
| Central queue, SecureObs-hosted scanner workers, credential broker, immutable job envelopes, independent policy workers | **Future architecture under consideration; not implemented today** |
| Security or business outcomes improved by a quantified amount | **Not claimed**; no supporting dataset is present |

## Scope and non-goals

In scope:

- customer-side scanner execution and its trust boundary;
- scanner configuration retrieval, normalized findings upload, deduplication, and build gating;
- multitenant API, PostgreSQL isolation, dashboard, CI integrations, authorization, failure semantics, observability, and future evolution;
- code, dependency, IaC, container, and other scanner classes only at the common orchestration and evidence boundary.

Not established by this case study:

- the names or coverage of the seven bundled scanners;
- the exact private API routes, token format, tables, deployment topology, hosting provider, customer count, service-level objective, or production incident history;
- that one scanner or the bundled set covers every vulnerability class;
- that customer pipeline execution is equivalent to an isolated hostile-code sandbox;
- a customer-specific compliance certification, penetration-test result, or guarantee that a passing build is vulnerability-free.

## Implemented today

### Current architecture

```
flowchart LR
  D["Developer change"] --> CI["Customer GitHub Actions or Azure DevOps pipeline"]
  CI --> SC["SecureObs scanner container in customer CI"]
  SC --> CFG["SecureObs API: enabled-scanner configuration"]
  CFG --> SC
  SC --> S1["Seven bundled scanners execute locally"]
  S1 --> N["Normalize findings in scanner boundary"]
  N --> ING["SecureObs .NET 8 API: authorized findings ingestion"]
  ING --> DD["Finding deduplication"]
  DD --> DB[("PostgreSQL: application authorization + FORCE RLS")]
  SC --> G["SecureObs build-gate call"]
  G --> CI
  UI["Angular 21 dashboard"] --> ING
  ING --> UI
```

The diagram deliberately contains no central SecureObs scan queue or hosted scanner worker. Source checkout, scanner processes, runner filesystem, build credentials, and local intermediate output remain inside the customer-controlled CI environment. The SecureObs boundary begins when the scanner authenticates to retrieve configuration or submit data and when the dashboard calls the API.

### Current execution sequence

1. A customer workflow starts the SecureObs scanner image in GitHub Actions or Azure DevOps.
2. The scanner retrieves the enabled-scanner configuration for the authorized customer/project context.
3. The scanner starts the seven bundled scanners against the pipeline workspace.
4. Scanner output is converted to the normalized SecureObs findings contract.
5. The scanner uploads normalized findings to the .NET 8 API.
6. The API applies application authorization and tenant-scoped PostgreSQL access with forced RLS, then ingests and deduplicates findings.
7. The scanner calls the build gate, and the customer pipeline consumes its response.
8. Authorized users review tenant-scoped state through the Angular 21 dashboard.

I can confirm this sequence exists as described. I'm not claiming to know the private authentication mechanism, retry protocol, atomicity boundary, gate-state machine, or the exact ordering of internal API/database operations — those are things I'd still need to review, not facts I'm inferring.

### Assets, actors, and trust boundaries

Primary assets are customer source and build workspace, pipeline credentials, SecureObs API credentials, enabled-scanner configuration, raw local scanner output, normalized findings, finding identity/deduplication state, policy/gate response, tenant membership, PostgreSQL rows, dashboard session, integration configuration, and audit evidence.

Relevant actors and failure sources include:

- an authorized tenant user substituting another tenant/project/object identifier;
- an untrusted pull request modifying workflow or scanner inputs;
- a compromised customer runner, action/task, dependency, or scanner image;
- malformed or adversarial scanner output reaching the normalization/ingestion path;
- a stolen API token or dashboard session;
- a tenant attempting duplicate, oversized, cross-tenant, or replayed uploads;
- an operator or database role with excessive cross-tenant authority;
- API, database, or gate outages creating ambiguous pipeline outcomes.

The customer and SecureObs share responsibility. SecureObs can authorize its API and isolate stored findings; it cannot make a customer-controlled runner trustworthy or remove permissions that the customer gave that runner.

### Current multitenant data boundary

The database design I've confirmed combines application authorization with PostgreSQL `FORCE ROW LEVEL SECURITY`. That is the right defense-in-depth shape: application code establishes whether a principal may perform an action, while RLS constrains which tenant rows the runtime role can read or change.

Security invariants that the private implementation should continuously prove:

- tenant/project authority comes from authenticated server-side relationships, never only a request header, route ID, or uploaded body;
- every tenant-owned table has a non-null tenant key and complete read/write policy;
- the application runtime role neither owns protected tables nor has `BYPASSRLS`;
- migrations and support access use separate, audited roles;
- transaction-local tenant context is always set, validated, and cleared by scope;
- foreign-key relationships cannot attach a tenant-A object to tenant B;
- lists, search, aggregates, exports, deduplication queries, and background maintenance preserve the same tenant boundary;
- caches, logs, object storage, analytics, backups, and support tools receive equivalent isolation even though PostgreSQL RLS cannot protect them.

The [PostgreSQL RLS lab](../labs/postgresql-rls/README.md) reproduces these database boundary properties using a public test schema. It is evidence for the pattern, not an assertion that the lab is the private SecureObs schema.

### Findings ingestion and deduplication boundary

Normalized findings are untrusted input even when uploaded by an authenticated pipeline. Recommended API invariants are:

- authorize tenant, project, repository, and upload action server-side;
- enforce versioned schema, size/count/depth limits, content types, and decompression bounds before expensive parsing;
- bind an upload to repository, commit or artifact digest, scanner name/version, configuration version, attempt identity, and observed time where available;
- use an idempotency key so retry does not create inconsistent state;
- compute or verify tenant-scoped deduplication keys server-side rather than trusting a client-supplied global fingerprint;
- prevent one tenant's deduplication lookup, conflict response, timing, or count from revealing another tenant's findings;
- distinguish scanner success with zero findings from execution failure, timeout, partial output, unsupported schema, and upload failure;
- preserve enough source evidence to explain why a finding was created, merged, reopened, suppressed, or resolved without retaining unnecessary secrets/source.

These are **recommended review criteria**. What I can confirm is that normalization, ingestion, and deduplication exist — not that every invariant above is already implemented.

### Build-gate boundary

The build gate is implemented, but this public repository does not establish its exact private decision state machine. A required gate should distinguish:

```text
PASS | POLICY_BLOCK | SCANNER_ERROR | CONFIG_ERROR | UPLOAD_ERROR | AUTH_ERROR | STALE
```

Only an explicit, current `PASS` bound to the intended tenant/project and immutable source/artifact should allow a protected release. Missing, malformed, stale, or unavailable evidence must not silently become green. Emergency bypass should require an owned, time-bounded, audited risk acceptance rather than an ignored exit code.

The [secure CI/CD lab](../labs/secure-cicd/README.md) reproduces fail-closed report and policy behavior with positive and negative fixtures. It does not claim byte-for-byte equivalence to the private SecureObs gate.

### GitHub Actions and Azure DevOps integrations

Because the scanner runs in customer CI, integration security is part of the product boundary:

- pin the scanner image by immutable digest for protected releases;
- document supported runner/container privileges and avoid mounting a host Docker socket or unrelated credentials unless strictly required;
- do not expose SecureObs or deployment credentials to untrusted fork pull requests;
- give the scanner only the repository/project and API scopes it needs;
- protect workflow/task definitions, environment approvals, branch rules, and service connections from untrusted modification;
- avoid passing tokens on command lines or including them in scanner output/logs;
- set bounded timeouts and resource limits for each bundled scanner;
- make configuration retrieval and findings upload use authenticated TLS and explicit retry/idempotency behavior;
- bind gate status to the exact commit/artifact rather than a mutable branch label.

These controls must be tested in both GitHub Actions and Azure DevOps because their fork, token, approval, identity, and logging semantics differ.

## Historical defects and fixes

I haven't attached any specific issue, incident, commit, or fix timeline here, so this write-up makes **no claim** that a particular defect occurred in SecureObs or affected a customer.

| Current fact | What may be said | What must not be inferred |
|----|----|----|
| PostgreSQL uses application authorization and forced RLS | These controls are implemented today | RLS was added after a cross-tenant incident or known vulnerability |
| Findings are normalized and deduplicated | These capabilities are implemented today | A past deduplication defect, its impact, or its fix date |
| A build gate exists | Customer pipelines can call a SecureObs gate today | A prior fail-open incident or the private gate's exact failure semantics |
| Scanner executes in customer CI | This is the current execution model | SecureObs migrated from a hosted worker fleet |

To promote an item into a genuine historical defect-and-fix narrative, add a sanitized record containing: affected component/version, discovery source, exploitability and customer-impact statement, root cause, control change, regression test, rollout and rollback evidence, and dates I can vouch for. If customer or security-sensitive detail cannot be published, retain the history privately and state only the verified lesson.

## Architecture limitations

### Customer-runner trust

The scanner inherits the security of the customer's runner, workflow, checkout, and credentials. A compromised runner can tamper with scanner inputs or outputs, steal available secrets, suppress execution, or call APIs outside the intended sequence. SecureObs does not currently provide a server-side isolated execution environment that removes this trust.

### Evidence authenticity and completeness

A normalized findings upload proves what the authenticated client submitted, not by itself that all seven scanners ran, that the approved image/configuration was used, or that output was not removed before upload. Stronger assurance requires immutable scanner identity/version, configuration and source/artifact binding, explicit per- scanner completion state, anti-replay controls, and authenticated evidence generated outside the repository's ability to forge it.

### Credential responsibility

There is no current SecureObs credential broker in this documented architecture. Repository, registry, cloud, and build credentials remain customer-managed within the pipeline. Customers must minimize scope/lifetime and prevent untrusted workflow code from receiving them; SecureObs must keep its own API credential narrow, revocable, and redacted.

### Availability and release coupling

Configuration retrieval, findings ingestion, and the build-gate call depend on the customer network and SecureObs API availability. A strict gate can delay releases during an outage; a fail-open gate weakens assurance. The product needs explicit timeouts, retry/idempotency, status communication, service objectives, cached-policy rules where safe, and a controlled emergency process.

### Heterogeneous scanner semantics

Seven bundled scanners do not naturally share exit codes, severity, confidence, fingerprints, locations, or completeness signals. Normalization can lose information or merge unrelated findings. Version each adapter and schema, retain scanner identity, test upgrades with golden/negative fixtures, and make deduplication reversible and explainable.

### Multistore isolation

Forced RLS protects covered PostgreSQL queries, not dashboard caches, logs, exports, object storage, metrics, backups, support tools, or external analytics. Each store and operational path requires an explicit tenant-isolation design and deletion/retention test.

## Current threat model and verification backlog

| Abuse/failure case | Current evidence | Required verification or improvement |
|----|----|----|
| Client supplies another tenant/project ID | Application authorization + forced RLS — I've confirmed this myself | route/body/header mutation tests across CRUD, lists, search, dedup, export, dashboard |
| Untrusted PR receives API/cloud/deploy credentials | Customer-side CI execution is confirmed | negative fork/PR tests for both GitHub and Azure DevOps; document safe templates |
| Scanner skips one tool but reports success | Seven-scanner execution and normalization are confirmed | per-scanner terminal states; missing/timeout/malformed-output negative cases |
| Upload is replayed for another commit | Binding details are not publicly verified | server-generated attempt/idempotency key and immutable commit/artifact/config binding |
| Duplicate finding crosses tenant boundary | Deduplication is confirmed | tenant included in every lookup/key/constraint; collision and timing-isolation tests |
| Runner tampers with output | Customer-runner limitation | authenticated evidence and stronger builder/scanner provenance where risk warrants |
| API/gate outage becomes green | Private semantics not verified | explicit fail-closed states plus audited emergency risk acceptance |
| Support/operator bypasses application layer | Private operations not verified | separate JIT role, case/approval, immutable audit, tests confirming direct store access is denied |
| Scanner/API token leaks in logs | Integration exists | secret-redaction tests, short-lived/narrow token, revocation drill |
| Oversized hostile report exhausts API | Normalized ingestion exists | byte/count/depth/decompression limits, streaming/quarantine, quota/rate tests |

## Future control-plane architecture under consideration

> **Not implemented today.** The services and flows in this section are a design option for future requirements. They must not be represented as the architecture currently running at `secureobs.com`.

```
flowchart LR
  U["Authorized tenant request or CI trigger"] --> API["Control-plane API"]
  API --> J["Immutable tenant-bound job envelope"]
  J --> Q["Tenant-aware queue"]
  Q --> W["Ephemeral isolated SecureObs worker"]
  W --> CB["Target-scoped credential broker"]
  W --> R["Untrusted raw scanner output"]
  R --> N["Independent schema/completeness normalizer"]
  N --> P["Independent versioned policy evaluator"]
  P --> D["Decision bound to job and artifact/source"]
  D --> C["CI status, dashboard, or webhook"]
```

This model may be justified if customers need centrally scheduled scans, passive cloud API posture checks, stronger hostile-source isolation, standardized execution evidence, or scanning outside CI. It would introduce new high-impact responsibilities:

- SecureObs would process customer source or target data in its own compute boundary;
- the platform would need job/tenant/target authorization at every transition;
- workers would require isolation tiers, egress control, resource limits, secure deletion, image/plugin verification, and no cross-job cache trust by default;
- a credential broker would need federation or short-lived target-specific grants and must never place reusable customer credentials in queue messages;
- queue duplication/reordering, leases, retries, partial upload, cancellation, and reconciliation would require monotonic/idempotent state transitions;
- policy evaluation should be independent from scanner success and bound to immutable evidence;
- source/data residency, customer consent, retention, incident response, cost, and service ownership would materially expand.

### Future migration gates

Do not begin that migration merely because hosted workers look architecturally mature. Require an approved threat model and ADR that compares:

1. current customer-side execution;
2. customer-hosted runner/agent with stronger attested configuration;
3. SecureObs-hosted container worker;
4. stronger VM/microVM or dedicated-tenant worker; and
5. passive API-only scanning that never executes customer code.

Before production, prove cross-tenant job and credential denial, hostile-repository containment, metadata/private-network blocking, queue replay/reorder handling, worker loss, evidence binding, deletion/restore, operator access, and bulk credential revocation. Rollback must stop new hosted work, revoke worker/customer grants, quarantine uncertain evidence, and return customers to the documented CI execution path without silently reusing incomplete results.

## Validation evidence

Repository-reproduced checks:

```powershell
npm ci --ignore-scripts
node labs/secure-cicd/tests/run-tests.js
./labs/postgresql-rls/run-tests.ps1
```

Private implementation tests still required before stronger claims:

- end-to-end GitHub Actions and Azure DevOps scanner runs for every bundled scanner;
- wrong/missing tenant, project, repository, membership, role, and action;
- cross-tenant CRUD, list, search, aggregation, deduplication, export, and dashboard;
- missing scanner, crash, timeout, malformed/oversized output, partial/replayed upload;
- wrong commit/artifact/configuration and stale gate response;
- fork pull request, modified workflow/task, token redaction, and revocation;
- PostgreSQL policy/role/schema drift plus cache/log/export/backup isolation;
- API/database outage, duplicate retry, recovery, and emergency gate procedure;
- tenant deletion, retention expiry, restore, support access, and incident exercise.

## Observability and operations

Correlate tenant/project, authenticated principal or pipeline identity, repository and commit/artifact, scanner image/configuration and seven per-scanner outcomes, upload and idempotency identity, schema version, finding/deduplication decision, gate policy and response, dashboard/API authorization decision, trace, and timing. Never log tokens or unnecessary source/finding secrets.

Alert on missing/invalid tenant context, RLS/runtime-role drift, cross-tenant authorization denial spikes, scanner completion gaps, malformed or oversized uploads, replay/idempotency conflicts, unusual finding-count collapse, gate errors near release, new scanner/image/configuration, operator cross-tenant activity, token anomalies, and tenant-specific rate/cost spikes.

Track security-control health separately from vulnerability counts: configuration retrieval success, each scanner's completed/failed/timed-out state, normalization and ingestion errors, deduplication collisions/merges, evidence latency, gate decision age, RLS isolation-test status, authorization denials, token age/revocation, and tenant deletion/restore verification.

## The cost, and what's still not solved

In the customer-side scanning path documented here, SecureObs does not pull the customer repository into a SecureObs-hosted worker, so it never takes custody of that source and those build credentials — but that also means trusting a wide range of customer runners and workflows I don't control. Strict evidence checks and outage handling can slow builds down. Strong tenant checks, forced RLS, schema validation, immutable subject binding, and detailed telemetry all cost real engineering, storage, support, and customer-configuration time.

What's still not solved: a compromised customer runner, scanner blind spots or a supply-chain compromise, forged or incomplete evidence from the client, normalization/deduplication bugs, stale authorization, a compromised operator or provider, stores outside PostgreSQL I haven't modeled, and unsafe customer workflow configuration. SecureObs can give you useful evidence and enforcement; it can't guarantee a workload is vulnerability-free.

## What I'd still want to check

The current-implementation statements above come from my own architecture correction, not from inspecting the private code independently. Before I'd call this `verified` instead of `partially-verified`, I'd want to review sanitized architecture/sequence diagrams, API authorization tests, RLS migration/policy tests, integration fixtures, scanner completion semantics, gate failure behavior, and operational evidence. Any historical defect claims need their own records I can point to. I'm not adding customer identity, private findings, secrets, or outcomes I can't back up.

## References

- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Azure Pipelines security guidance](https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)
- [OWASP ASVS project](https://owasp.org/www-project-application-security-verification-standard/)
