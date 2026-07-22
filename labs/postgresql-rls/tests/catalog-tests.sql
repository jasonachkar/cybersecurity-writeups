\set ON_ERROR_STOP on
\pset pager off

DO $$
DECLARE
  problem_count integer;
BEGIN
  SELECT count(*) INTO problem_count
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app'
    AND c.relkind IN ('r', 'p')
    AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);
  IF problem_count <> 0 THEN
    RAISE EXCEPTION '% application table(s) lack ENABLE/FORCE ROW LEVEL SECURITY', problem_count;
  END IF;

  SELECT count(*) INTO problem_count
  FROM pg_roles
  WHERE rolname IN ('tenant_runtime', 'tenant_migrator')
    AND (rolsuper OR rolbypassrls);
  IF problem_count <> 0 THEN
    RAISE EXCEPTION 'runtime or migration role can bypass row security';
  END IF;

  SELECT count(*) INTO problem_count
  FROM pg_policies
  WHERE schemaname = 'app'
    AND tablename = 'customer_record'
    AND policyname = 'tenant_isolation'
    AND qual IS NOT NULL
    AND with_check IS NOT NULL;
  IF problem_count <> 1 THEN
    RAISE EXCEPTION 'tenant policy must contain both USING and WITH CHECK expressions';
  END IF;
END;
$$;

\echo 'PASS: catalog tests confirm ENABLE/FORCE RLS, non-bypass roles, and complete policy expressions'
