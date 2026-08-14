---
title: "Engineering Tenant Isolation for a Multi-tenant SaaS Platform"
type: "appsec"
tags:
  - appsec
  - saas
  - multitenancy
  - isolation
date: "2026-07-25"
lastReviewed: "2026-07-25"
readingTime: 12
reviewStatus: "partially-verified"
validatedAgainst:
  - "PostgreSQL row security policies — https://www.postgresql.org/docs/current/ddl-rowsecurity.html"
  - "PostgreSQL system administration functions — https://www.postgresql.org/docs/current/functions-admin.html"
  - "PostgreSQL `pg_class` catalog — https://www.postgresql.org/docs/current/catalog-pg-class.html"
  - "PostgreSQL role attributes — https://www.postgresql.org/docs/current/role-attributes.html"
  - "PostgreSQL supported versions — https://www.postgresql.org/support/versioning/"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "partially-tested"
reviewIntervalDays: 90
---

# Engineering Tenant Isolation for a Multi-tenant SaaS Platform

Tenant isolation is a layered authorization property, not a feature supplied by one SQL policy. The recommended design derives tenant context from authenticated server- side authorization, carries it through a transaction, enforces it again in the data plane, and continuously tests the identities that can bypass that boundary.

The companion [`labs/postgresql-rls`](../labs/postgresql-rls/README.md) lab exercises the PostgreSQL mechanics. It does not claim that a database policy alone makes an entire SaaS product isolated.

## The core decision

For the relational data path in scope, use shared tables with a non-null `tenant_id`, PostgreSQL row-level security (RLS), transaction-local tenant context, complete `USING` and `WITH CHECK` expressions, forced RLS for table owners, and application roles that are neither superusers nor `BYPASSRLS`.

RLS is defense in depth behind application authorization. Authentication establishes the principal; server-side membership/entitlement data establishes the allowed tenant; application authorization establishes the action; RLS constrains rows. A client-provided header, route value, JWT claim, or GraphQL argument is an input to validate, never authority by itself.

## Scope and non-goals

In scope:

- interactive and service API access to tenant-owned PostgreSQL rows;
- tenant context propagation through a pooled database connection;
- ordinary read and write isolation, administrative bypass governance, and schema checks;
- rollout, testing what should be denied, logging, and incident hooks.

Not established by this design:

- isolation of object storage, caches, queues, analytics, search indexes, backups, logs, or observability systems;
- protection from a database superuser, compromised host, malicious database extension, or exploitable database engine;
- per-tenant cryptographic isolation or a hard multi-tenant kernel boundary;
- correct product entitlements or business authorization above the row boundary.

## Assets, actors, and trust boundaries

Primary assets are tenant data, membership and entitlements, audit evidence, administrative credentials, export jobs, and tenant-scoped encryption references. Threat actors include a legitimate user selecting another tenant, a compromised API credential, a confused-deputy background job, an operator using a bypass identity, and a faulty migration or connection-pool integration.

```
flowchart LR
  C["Untrusted client input"] --> I["Identity provider"]
  I --> A["API authentication"]
  C --> A
  A --> Z["Server-side membership and authorization"]
  Z --> T["Transaction boundary sets tenant context"]
  T --> R["Non-bypass runtime role"]
  R --> P["PostgreSQL RLS USING and WITH CHECK"]
  P --> D[("Tenant rows")]
  A --> Q["Queue message with authenticated tenant binding"]
  Q --> W["Worker authorization and transaction"]
  W --> R
  B["Break-glass or migration identity"] -. audited bypass .-> D
```

The most important boundary is between untrusted tenant selectors and the server-established authorization result. Copying `X-Tenant-ID` directly into a database session setting is an insecure direct object reference with extra steps.

## Threat model and abuse cases

| Abuse case | Preventive controls | Detection and negative evidence |
|----|----|----|
| User substitutes another tenant ID | Membership lookup and action authorization; opaque identifiers are not relied upon | Cross-tenant API and direct SQL tests; authorization-denial metric |
| Query omits tenant predicate | RLS policy on every tenant table | Catalog test plus a query without an application predicate |
| Insert/update changes `tenant_id` | Non-null tenant key and `WITH CHECK` | Cross-tenant insert/update tests |
| Pooled connection retains prior tenant | Transaction-local `set_config(..., true)`; transaction wrapper owns lifecycle | Reuse the same session across transactions and assert missing context afterward |
| Missing context broadens access | Policy expression matches no row; writes fail | Missing-context read/write tests |
| Malformed context triggers fallback | No fallback; cast error fails the operation | Invalid UUID context test |
| Table owner silently bypasses | `FORCE ROW LEVEL SECURITY`; separate migration/runtime roles | `relforcerowsecurity` catalog assertion |
| Runtime role gains bypass | `NOSUPERUSER NOBYPASSRLS`; restricted role administration | Alert/test on `rolsuper` or `rolbypassrls` |
| New table ships without RLS | migration guard and schema inventory | Catalog check fails for every in-scope ordinary/partitioned table |
| Export/worker acts as confused deputy | Signed/internal job metadata plus server-side reauthorization | Cross-tenant job fixtures and audit event correlation |

## Architecture decision record

### Selected option

Shared PostgreSQL tables with defense-in-depth RLS are selected for the baseline transactional workload. This keeps schema evolution and aggregate operations manageable while placing a consistent tenant filter below ordinary ORM/query code.

### Alternatives considered

| Option | Benefits | Costs and appropriate use |
|----|----|----|
| Database per tenant | Strong administrative and failure-domain separation | Connection, migration, backup, observability, and fleet cost; useful for regulated or very large tenants |
| Schema per tenant | Namespace separation with shared server | Schema fleet complexity; search path and migration hazards; not equivalent to separate databases |
| Shared tables without RLS | Simple database permissions | Every query path must be correct; one missed predicate becomes a breach |
| Shared tables with RLS | Central row constraint and testable catalog | Bypass identities, context propagation, non-row stores, and policy performance remain operational responsibilities |

The choice is reversible only with deliberate data-migration tooling. A product may offer multiple isolation tiers rather than forcing every tenant onto one topology.

## Control design

### Establish tenant authority server-side

After validating token issuer, signature, time claims, and intended audience, resolve the subject to current server-side membership. If a request names a tenant, compare it to that authorized set. For service identities, bind workload identity to an explicit tenant/service entitlement. Cache membership carefully: revocation latency is part of the authorization design.

Do not permit a general request header to select the database tenant without this check. An API gateway may propagate an internal signed identity context, but the receiving service still validates its origin, audience, freshness, and authorization.

### Use one transaction as the context lifetime

The tested SQL pattern is:

<div class="language-sql highlight">

<span id="__span-0-1"><span class="c1">`-- Tested in labs/postgresql-rls.`</span>` `</span><span id="__span-0-2"><span class="k">`BEGIN`</span><span class="p">`;`</span>` `</span><span id="__span-0-3"><span class="k">`SELECT`</span><span class="w">` `</span><span class="n">`set_config`</span><span class="p">`(`</span><span class="s1">`'app.tenant_id'`</span><span class="p">`,`</span><span class="w">` `</span><span class="err">`$`</span><span class="mi">`1`</span><span class="p">`,`</span><span class="w">` `</span><span class="k">`true`</span><span class="p">`);`</span>` `</span><span id="__span-0-4"><span class="c1">`-- All tenant queries use this same transaction/connection.`</span>` `</span><span id="__span-0-5"><span class="k">`COMMIT`</span><span class="p">`;`</span>` `</span>

</div>

The third argument `true` makes `set_config` transaction-local. The application must not return a rows iterator whose transaction has already committed, and must not set context on one pooled connection before executing work on another. Use a helper that accepts a callback, sets context, executes all work, and commits only after the callback closes its rows/results.

### Enforce read and write predicates

The lab applies this expression:

<div class="language-sql highlight">

<span id="__span-1-1"><span class="c1">`-- Tested in labs/postgresql-rls/init/001-schema.sql.`</span>` `</span><span id="__span-1-2"><span class="k">`ALTER`</span><span class="w">` `</span><span class="k">`TABLE`</span><span class="w">` `</span><span class="n">`app`</span><span class="p">`.`</span><span class="n">`customer_record`</span><span class="w">` `</span><span class="n">`ENABLE`</span><span class="w">` `</span><span class="k">`ROW`</span><span class="w">` `</span><span class="k">`LEVEL`</span><span class="w">` `</span><span class="k">`SECURITY`</span><span class="p">`;`</span>` `</span><span id="__span-1-3"><span class="k">`ALTER`</span><span class="w">` `</span><span class="k">`TABLE`</span><span class="w">` `</span><span class="n">`app`</span><span class="p">`.`</span><span class="n">`customer_record`</span><span class="w">` `</span><span class="k">`FORCE`</span><span class="w">` `</span><span class="k">`ROW`</span><span class="w">` `</span><span class="k">`LEVEL`</span><span class="w">` `</span><span class="k">`SECURITY`</span><span class="p">`;`</span>` `</span><span id="__span-1-4">` `</span><span id="__span-1-5"><span class="k">`CREATE`</span><span class="w">` `</span><span class="n">`POLICY`</span><span class="w">` `</span><span class="n">`tenant_isolation`</span><span class="w">` `</span><span class="k">`ON`</span><span class="w">` `</span><span class="n">`app`</span><span class="p">`.`</span><span class="n">`customer_record`</span>` `</span><span id="__span-1-6"><span class="w">` `</span><span class="k">`FOR`</span><span class="w">` `</span><span class="k">`ALL`</span><span class="w">` `</span><span class="k">`TO`</span><span class="w">` `</span><span class="n">`tenant_runtime`</span><span class="p">`,`</span><span class="w">` `</span><span class="n">`tenant_migrator`</span>` `</span><span id="__span-1-7"><span class="w">` `</span><span class="k">`USING`</span><span class="w">` `</span><span class="p">`(`</span>` `</span><span id="__span-1-8"><span class="w">` `</span><span class="n">`tenant_id`</span><span class="w">` `</span><span class="o">`=`</span><span class="w">` `</span><span class="k">`NULLIF`</span><span class="p">`(`</span><span class="n">`current_setting`</span><span class="p">`(`</span><span class="s1">`'app.tenant_id'`</span><span class="p">`,`</span><span class="w">` `</span><span class="k">`true`</span><span class="p">`),`</span><span class="w">` `</span><span class="s1">`''`</span><span class="p">`)::`</span><span class="n">`uuid`</span>` `</span><span id="__span-1-9"><span class="w">` `</span><span class="p">`)`</span>` `</span><span id="__span-1-10"><span class="w">` `</span><span class="k">`WITH`</span><span class="w">` `</span><span class="k">`CHECK`</span><span class="w">` `</span><span class="p">`(`</span>` `</span><span id="__span-1-11"><span class="w">` `</span><span class="n">`tenant_id`</span><span class="w">` `</span><span class="o">`=`</span><span class="w">` `</span><span class="k">`NULLIF`</span><span class="p">`(`</span><span class="n">`current_setting`</span><span class="p">`(`</span><span class="s1">`'app.tenant_id'`</span><span class="p">`,`</span><span class="w">` `</span><span class="k">`true`</span><span class="p">`),`</span><span class="w">` `</span><span class="s1">`''`</span><span class="p">`)::`</span><span class="n">`uuid`</span>` `</span><span id="__span-1-12"><span class="w">` `</span><span class="p">`);`</span>` `</span>

</div>

`current_setting(..., true)` returns null when the custom setting is absent. The comparison then matches no row. An empty setting becomes null; a malformed nonempty UUID raises an error. `USING` restricts visible/existing rows; `WITH CHECK` restricts new row values after an insert or update.

### Separate runtime, migration, and break-glass roles

- Runtime role: only required DML/functions; `NOSUPERUSER NOBYPASSRLS`; does not own tables or roles.
- Migration role: owns schema objects, is still forced through RLS for ordinary data operations, and is unavailable to the application.
- Break-glass/managed administrator: may bypass by platform design; requires strong authentication, just-in-time access, separate device/session controls, approval, query/audit logging, and post-use review.

PostgreSQL documents that superusers and `BYPASSRLS` roles always bypass RLS. Table owners normally bypass it unless `FORCE ROW LEVEL SECURITY` is enabled. These are design facts to govern, not edge cases to hide.

### Cover every data path

Maintain an ownership inventory for tables, partitions, views, functions, materialized views, logical replication, exports, background jobs, caches, object stores, search, analytics, and support tooling. Security-definer functions need explicit ownership, fixed `search_path`, minimal grants, and targeted review. Avoid exposing arbitrary SQL through administrative features.

## Failure modes

### Database dependency or transaction failure

Fail the request. Never retry outside the authorization/tenant wrapper. A retry must create a new transaction, re-establish context, and remain idempotent where required.

### Missing or invalid tenant context

Reads should return no tenant rows and writes should fail. Treat either as a security telemetry event because it indicates an integration or attack path. Do not substitute a default tenant.

### Policy or migration rollout failure

Adding RLS before all code supplies context can create an availability incident; adding context before RLS can leave a security gap. Use a staged rollout:

1. inventory tables, roles, owners, policies, and bypass paths;
2. add non-null tenant keys and validate backfill integrity;
3. deploy transaction-scoped context and observe missing-context counters;
4. enable RLS in a canary/staging environment and confirm cross-tenant access actually fails;
5. enable and force RLS table by table with rollback rehearsed;
6. remove broad grants and monitor catalog drift.

Rollback must not mean silently disabling RLS in production. Prefer rolling back the offending application release or routing to a known-good version. Any emergency RLS disablement is a declared security incident with compensating isolation and review.

### Performance regression

Index tenant keys with access patterns, inspect query plans under representative tenant cardinalities, and test partitions. Do not weaken the policy to repair a slow query. Resolve indexing/query design and watch plan changes across PostgreSQL updates.

## Validation evidence

Run the disposable PostgreSQL 18.4 lab:

<div class="language-powershell highlight">

<span id="__span-2-1"><span class="p">`./`</span><span class="n">`labs`</span><span class="p">`/`</span><span class="n">`postgresql-rls`</span><span class="p">`/`</span><span class="n">`run-tests`</span><span class="p">`.`</span><span class="n">`ps1`</span>` `</span>

</div>

It validates:

- own-tenant read and cross-tenant read/update denial;
- cross-tenant and missing-context write rejection;
- malformed context failure;
- transaction-local context clearing on SQL-session and `pg` pool physical-session reuse;
- rollback and absent context after a query error and statement-timeout cancellation;
- simultaneous tenant-A and tenant-B transactions on separate pooled sessions;
- `relrowsecurity` and `relforcerowsecurity` on in-scope tables;
- both policy expressions and non-bypass application roles.

Application suites must extend this narrow `pg` proof across every endpoint and background job, each supported pool/ORM mode, route/body/header tenant selectors, errors, cancellations, concurrency, retries, and both response and database state. Equivalent tests are still required for queues, caches, object storage, search, analytics, exports, and telemetry. Run schema catalog checks after every migration.

## Observability and operations

Collect without putting sensitive row contents in logs:

- authorization decision, principal ID, authoritative tenant ID, action, outcome, policy version, request/trace ID, and service identity;
- missing/malformed context counters and RLS-related database errors;
- cross-tenant test results in release evidence;
- role and schema drift (`rolsuper`, `rolbypassrls`, table owner, RLS flags, policy expressions, grants, security-definer functions);
- break-glass activation, queries, approvals, duration, and review outcome;
- exports, large result sets, support impersonation, and unusual tenant switching.

Alert on any runtime role bypass, a new tenant table without forced RLS, sustained missing context, unexplained cross-tenant authorization denials, or break-glass use. Telemetry access is itself multi-tenant sensitive and needs least privilege.

## The cost, and what's still not solved

RLS isn't free: it adds real policy design, test, and query-planning work. Operators lose some convenience because admin access now has to be deliberate and audited rather than a raw connection. Support impersonation needs its own product controls instead of someone just hitting the database directly.

What can still go wrong: compromised bypass credentials, bugs in the database engine itself, stores that don't fit the row model, side channels, application authorization that's too broad, stale membership data, unsafe functions, and migration mistakes. Tenants that need a harder failure boundary than this may need separate databases, separate accounts/subscriptions, or their own encryption keys on top of all this.

## Limitations

The lab validates PostgreSQL behavior and the `pg` 8.22.0 pool lifecycle in one disposable version and topology. It does not validate another client, an ORM or framework transaction wrapper, a managed PostgreSQL service, API authorization, identity-provider integration, or a production dataset. Re-run on supported production versions and record provider-specific administrator/bypass behavior.

## Operational checklist

Tenant authority is server-side and action-specific.

Every transaction sets context locally; no default tenant exists.

Every tenant table has a non-null tenant key, `ENABLE` and `FORCE` RLS, and complete read/write policy expressions.

Runtime identities are non-owner, non-superuser, and `NOBYPASSRLS`.

Non-row stores and asynchronous jobs have equivalent isolation tests.

Tests confirming denied cases stay denied run after migrations and before releases.

Break-glass is just-in-time, approved, logged, and reviewed.

Catalog drift and missing context are alertable.

What's still not solved, and any tenant-specific isolation tier, is written down.

## References

- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL system administration functions](https://www.postgresql.org/docs/current/functions-admin.html)
- [PostgreSQL `pg_class` catalog](https://www.postgresql.org/docs/current/catalog-pg-class.html)
- [PostgreSQL role attributes](https://www.postgresql.org/docs/current/role-attributes.html)
- [PostgreSQL supported versions](https://www.postgresql.org/support/versioning/)
