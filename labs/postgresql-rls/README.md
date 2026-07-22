# PostgreSQL row-level security isolation lab

This disposable lab tests a transaction-scoped tenant context, complete `USING` and
`WITH CHECK` policies, forced row security, and role properties that prevent ordinary
application identities from bypassing the boundary.

## Prerequisites and tested versions

- Docker Engine or Docker Desktop with Compose v2.
- PowerShell 7+ on Windows or a POSIX shell on Linux/macOS.
- Image: `postgres:18.4-alpine3.24`, pinned to the current PostgreSQL 18.4 patch
  release checked on 2026-07-21. For a long-lived environment, pin the image digest
  in the deployment's own dependency process.

## Run

PowerShell:

```powershell
./labs/postgresql-rls/run-tests.ps1
```

POSIX shell:

```sh
./labs/postgresql-rls/run-tests.sh
```

The scripts generate an ephemeral local database password, start the service, run
runtime and catalog tests, and remove containers and volumes. Pass `-Keep` or
`--keep` to retain the service for inspection.

Expected output includes `PASS` messages for cross-tenant reads/writes, missing and
malformed context, connection reuse, RLS catalog flags, non-bypass role attributes,
and policy expressions. Any SQL error or failed assertion returns a nonzero status.

## Security properties exercised

- Tenant identity is set with transaction-local `set_config(..., true)`; it does not
  leak into the next transaction on a pooled connection.
- Missing context matches no rows and fails writes. Malformed UUID context raises an
  error instead of falling back to a broader scope.
- Both row visibility and new row values are constrained.
- `FORCE ROW LEVEL SECURITY` applies policy to the table owner in ordinary use.
- Catalog tests use `relrowsecurity` and `relforcerowsecurity` and reject
  `rolsuper`/`rolbypassrls` on application roles.

## Limitations

The test connects as the local database administrator and uses `SET ROLE` to exercise
the non-bypass runtime identity. It does not model managed-service administrator
roles, network controls, connection-pool middleware, migration orchestration,
replication, backups, side channels, or application authorization. PostgreSQL
superusers and roles with `BYPASSRLS` bypass RLS by design; they require separate
administrative controls and monitoring.

## References

- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL system administration functions](https://www.postgresql.org/docs/current/functions-admin.html)
- [PostgreSQL `pg_class` catalog](https://www.postgresql.org/docs/current/catalog-pg-class.html)
- [PostgreSQL role attributes](https://www.postgresql.org/docs/current/role-attributes.html)
