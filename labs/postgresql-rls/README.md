# PostgreSQL row-level security isolation lab

This disposable lab tests a transaction-scoped tenant context, complete `USING` and `WITH CHECK` policies, forced row security, and role properties that prevent ordinary application identities from bypassing the boundary.

## Prerequisites and tested versions

- Docker Engine or Docker Desktop with Compose v2.
- PowerShell 7+ on Windows or a POSIX shell on Linux/macOS.
- Node.js 22+ and npm for the application integration test.
- Maintained PostgreSQL client: `pg` `8.22.0`, lockfile pinned.
- Image: `postgres:18.4-alpine3.24`, pinned to the PostgreSQL 18.4 patch release checked on 2026-07-21. For a long-lived environment, pin the image digest in the deployment's own dependency process.

## Run

PowerShell:

<div class="language-powershell highlight">

<span id="__span-0-1"><span class="p">`./`</span><span class="n">`labs`</span><span class="p">`/`</span><span class="n">`postgresql-rls`</span><span class="p">`/`</span><span class="n">`run-tests`</span><span class="p">`.`</span><span class="n">`ps1`</span>` `</span>

</div>

POSIX shell:

<div class="language-sh highlight">

<span id="__span-1-1">`./labs/postgresql-rls/run-tests.sh `</span>

</div>

The scripts generate an ephemeral local password, install the lockfile-pinned `pg` client, start the service, run SQL runtime/boundary/catalog suites plus the pooled-client suite, and remove containers and volumes. The password is not persisted in a tracked file. Pass `-Keep` or `--keep` to retain the service for inspection.

Expected output includes `PASS` messages for cross-tenant reads and writes, mutation of a visible row's tenant key, missing and malformed context, connection reuse, forced RLS for the table owner, catalog flags, non-bypass role attributes, policy count, policy roles, and complete policy expressions. Any SQL error or failed assertion returns a nonzero status.

## Security properties exercised

- Tenant identity is set with transaction-local `set_config(..., true)`; it does not leak into the next transaction on a pooled connection.
- Missing context matches no rows and fails writes. Malformed UUID context raises an error instead of falling back to a broader scope.
- Both row visibility and new row values are constrained, including an attempted update that moves a visible row into a different tenant.
- `FORCE ROW LEVEL SECURITY` is exercised while running as the table owner.
- Catalog tests reject missing RLS flags, bypass-capable application roles, extra policies, unexpected policy roles, and absent or trivially true expressions.

## Application integration boundary

Every request and background job must establish the tenant inside the same database transaction as the protected queries. A background worker is not implicitly a system-wide tenant: it should process one explicit tenant per transaction, or use a separate narrowly scoped maintenance role and separately reviewed policy. Do not place a connection in a pool after a session-scoped tenant setting.

## Limitations

The test connects as the local database administrator and uses `SET ROLE` to exercise non-bypass identities. It does not model managed-service administrator roles, network controls, connection-pool middleware, migration orchestration, replication, backups, side channels, or application authorization. PostgreSQL superusers and roles with `BYPASSRLS` bypass RLS by design; they require separate administrative controls and monitoring.

## References

- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL system administration functions](https://www.postgresql.org/docs/current/functions-admin.html)
- [PostgreSQL `pg_class` catalog](https://www.postgresql.org/docs/current/catalog-pg-class.html)
- [PostgreSQL role attributes](https://www.postgresql.org/docs/current/role-attributes.html)
