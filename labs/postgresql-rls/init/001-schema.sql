\set ON_ERROR_STOP on

CREATE ROLE tenant_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE tenant_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

CREATE SCHEMA app AUTHORIZATION tenant_migrator;
GRANT USAGE ON SCHEMA app TO tenant_runtime;

SET ROLE tenant_migrator;

CREATE TABLE app.customer_record (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE app.customer_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.customer_record FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON app.customer_record
    FOR ALL
    TO tenant_runtime, tenant_migrator
    USING (
        tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON app.customer_record TO tenant_runtime;
RESET ROLE;

COMMENT ON POLICY tenant_isolation ON app.customer_record IS
    'Fail-closed tenant context: absent context sees no rows; malformed UUID raises an error; writes require the active tenant.';
