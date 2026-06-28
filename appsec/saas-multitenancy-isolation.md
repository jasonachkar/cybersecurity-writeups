---
title: "SaaS Multi-Tenancy Isolation Patterns: Database Segregation, PostgreSQL RLS, and Session Context Security"
type: appsec
tags: [Multi-Tenancy, Database Security, PostgreSQL RLS, SaaS, Isolation]
date: 2026-06
readingTime: 20
---

# SaaS Multi-Tenancy Isolation Patterns: Database Segregation, PostgreSQL RLS, and Session Context Security

## Executive Summary

Multi-tenant SaaS applications serve multiple customers (tenants) using shared infrastructure. The critical challenge in SaaS design is ensuring absolute data isolation between these tenants. A failure in tenant isolation is one of the most severe vulnerabilities a SaaS platform can suffer, leading directly to data breaches, compliance violations, and loss of customer trust. Many engineering teams rely solely on application-layer logic (such as appending a `tenant_id` where clause to SQL queries) to enforce isolation. This approach is highly fragile; a single developer oversight or missed query filter exposes customer data to other tenants.

At scale, relying on application developers to remember to filter every database query is unsustainable. Security must be enforced at the data layer. This whitepaper analyzes the primary database isolation models—database-per-tenant, schema-per-tenant, and shared-database with Row-Level Security (RLS). It focuses on the cryptographic and database configurations required to implement PostgreSQL RLS, highlights the risks of connection pool context pollution, and outlines defensive design patterns to secure tenant context.

---

## Threat Model and Attack Surface

The multi-tenant threat model assumes a malicious tenant is actively attempting to read or modify data belonging to other tenants using valid, authenticated API sessions.

```
                  [ Authenticated Tenant A Client ]
                                  │
                  ( Submits Request with Tenant B ID )
                                  │
                                  ▼
                     [ API Gateway / Controller ]
                                  │
                 ( Fails to validate tenant context )
                                  │
                                  ▼
                        [ Connection Pool ]
                                  │
               ( Reuses session: Tenant context remains A )
                                  │
               ┌──────────────────┴──────────────────┐
               ▼                                     ▼
 [ Query passes: Returns Tenant B data ] [ RLS active: Throws Access Denied ]
         ( Isolation Escape )                        ( Protected )
```

### Threat Vectors and Kill-Chains

1. **Horizontal Privilege Escalation (IDOR)**:
   - *Adversary Goal*: Access resources belonging to another tenant.
   - *Attack Vector*: An attacker logs into their tenant account and modifies a path parameter in an API request: `/api/v1/orders/10214` to `/api/v1/orders/10215`. If the application controller fetches the record directly by its primary key ID without verifying that the record's `tenant_id` matches the user's active tenant session, the data is returned to the unauthorized client.
2. **Connection Pool Session Contamination**:
   - *Adversary Goal*: Hijack database sessions to execute queries in another tenant's context.
   - *Attack Vector*: In high-throughput systems, database connections are pooled and shared across requests. If tenant context is set using session-level variables (e.g. `SET local app.current_tenant = 'tenant-a'`) and the connection is returned to the pool without being reset, a subsequent request from a different tenant reuses the connection and inherits the previous tenant's context, exposing their data.
3. **Implicit Bypass in Application Frameworks (ORM mapping)**:
   - *Adversary Goal*: Exploit query vulnerabilities to bypass tenant scoping.
   - *Attack Vector*: Developers write raw database queries or utilize ORM methods that bypass global query filters. If tenant scoping is not applied automatically by the data access layer, developers can easily run queries that return data from multiple tenants.

---

## Deep Technical Body

### Database Isolation Models

To isolate tenant data, choose the model that best balances security, operational complexity, and cost:

| Isolation Model | Security Level | Cost Efficiency | Operational Complexity |
| :--- | :--- | :--- | :--- |
| **Database-per-tenant** | **Highest**: Physical separation. Network rules and distinct encryption keys can isolate each database. | **Lowest**: Underutilized compute resources increase infrastructure costs. | **High**: Managing schema updates, backups, and migrations across hundreds of databases is complex. |
| **Schema-per-tenant** | **Medium**: Logical separation within a single database. Custom roles restrict access to specific schemas. | **Medium**: Shared database resources lower costs, but database engines limit the number of active schemas. | **Medium**: Schema migrations require orchestrating multiple updates in sequence. |
| **Shared-database with RLS** | **High**: Single database, single schema. Row-level security policies enforce isolation at the database level. | **Highest**: Maximum resource utilization and lowest operational cost. | **Low**: Single schema simplifies migrations, but writing secure RLS policies requires careful design. |

### PostgreSQL Row-Level Security (RLS) Policy Design

PostgreSQL Row-Level Security (RLS) allows administrators to define security policies that control access to tables based on user characteristics or session variables.

#### Step 1: Enable RLS on the Table
```sql
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
```

#### Step 2: Define the Security Policy
Instead of relying on database user roles (which is impractical for applications using connection pools with a single login role), use session variables to propagate the tenant ID:

```sql
CREATE POLICY tenant_isolation_policy ON orders
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), ''));
```

#### Step 3: Enforce Policy on Table Owners
By default, the table owner (typically the application migration role) is exempt from RLS policies. To prevent application roles from bypassing RLS, enforce policies on the owner as well:
```sql
ALTER TABLE orders FORCE ROW LEVEL SECURITY;
```

### Connection Pool Context Pollution

When using connection pooling (with libraries like `pgx`, `HikariCP`, or `SQLAlchemy`), multiple web requests share database connections. If a request sets a session variable and does not reset it, that variable remains active on the connection.

```
Request 1 (Tenant A) -> Get Conn from Pool -> SET app.current_tenant = 'tenant-a' -> Run Query -> Return Conn
                                                                                                      │
                                                                                                      ▼
Request 2 (Tenant B) -> Get Conn from Pool -> Run Query (Forgot to SET app.current_tenant!) -> Returns Tenant A data!
```

#### The Mitigation Strategy: Transaction-Scoped Settings
To prevent context pollution, use transaction-scoped settings by passing `true` as the third parameter to `set_config`. This ensures the session variable is automatically cleared when the transaction commits or rolls back:

```sql
-- The 'true' parameter restricts the variable scope to the current transaction
SELECT set_config('app.current_tenant', 'tenant-a', true);
```

Always wrap database operations in a transaction block. If an application retrieves a connection from the pool, it must run `set_config` within the transaction immediately after opening the connection, or configure the connection pool lifecycle to reset settings before returning connections to the pool.

---

## Defensive Architecture

A secure multi-tenant architecture must enforce tenant isolation at the data tier, validate tenant context on every request, and prevent cross-tenant operations.

### Tenant Context Validation Engine Pattern (Go Middleware)

This middleware interceptor extracts the tenant ID from the authenticated user token, validates it, and injects it into the database transaction context.

```go
package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
)

type contextKey string
const TenantIDKey contextKey = "tenant_id"

// TenantIsolationMiddleware extracts tenant context from JWT claims
func TenantIsolationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In production, extract this value from authenticated JWT claims
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			http.Error(w, "Missing tenant context", http.StatusUnauthorized)
			return
		}

		// Inject tenant context into request context
		ctx := context.WithValue(r.Context(), TenantIDKey, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ExecuteTenantQuery executes queries within the tenant's database context
func ExecuteTenantQuery(ctx context.Context, db *sql.DB, query string, args ...interface{}) (*sql.Rows, error) {
	tenantID, ok := ctx.Value(TenantIDKey).(string)
	if !ok {
		return nil, fmt.Errorf("tenant context missing from request execution context")
	}

	// Begin Transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() // Safe rollback if transaction fails

	// Enforce session context within transaction (local scope)
	_, err = tx.ExecContext(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID)
	if err != nil {
		return nil, err
	}

	// Execute target query
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	// Commit Transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return rows, nil
}
```

---

## Tooling and Implementation

Implement database validation and testing tools to verify tenant isolation:

1. **PostgreSQL RLS Audit Utilities**: Write automated integration tests that attempt to query data from Tenant B using a database connection configured with Tenant A's context. These tests must throw errors or return empty sets to prove RLS is active.
2. **Prisma / Hibernate Tenant Filters**: Use ORM-level tenant filtering tools (e.g. Hibernate `@FilterDef` or Prisma Client extensions) to append tenant ID checks to all queries automatically, providing a second layer of defense.
3. **Database Migration Linter**: Deploy migration linters to verify that all newly created tables have RLS enabled and FORCE ROW LEVEL SECURITY configured.

---

## SaaS Tenant Isolation Audit Checklist

| Item | Focus Area | Verification Step / Command | Target State |
| :--- | :--- | :--- | :--- |
| 1 | RLS Enablement | Check if all tables storing tenant data have RLS enabled. | `SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';` returns `true` for all tenant tables. |
| 2 | Owner Enforcement | Verify if RLS is enforced on table owners. | `SELECT relname, relforcepayload FROM pg_class WHERE relname = 'orders';` confirms RLS is forced. |
| 3 | Transaction Scope | Inspect database connection scripts to verify how session context is set. | Config settings are applied using transaction-scoped `set_config(..., true)` commands. |
| 4 | Connection Cleanup | Audit pool configurations to verify if connections are reset before reuse. | Pool settings contain connection reset or validation hooks. |
| 5 | IDOR Prevention | Review controller endpoints to verify that IDOR checks are active. | Access checks verify that the user's active tenant owns the requested resource ID. |
| 6 | Encryption Isolation | Check if data is encrypted using tenant-specific keys. | Key management systems use separate KMS keys mapped per tenant where required by compliance rules. |

---

## References

* *PostgreSQL Row-Level Security Policies*: [PostgreSQL Documentation](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
* *AWS SaaS Tenant Isolation Architectures*: [AWS SaaS Factory Whitepaper](https://docs.aws.amazon.com/whitepapers/latest/saas-tenant-isolation-strategies/saas-tenant-isolation-strategies.html)
* *Architecting Multi-Tenant SaaS Databases*: [Microsoft Azure Architecture Guide](https://docs.microsoft.com/en-us/azure/sql-database/saas-tenancy-app-design-patterns)
