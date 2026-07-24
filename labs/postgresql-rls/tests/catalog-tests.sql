\set ON_ERROR_STOP on
\pset pager off

DO $$
DECLARE
  problem_count integer;
BEGIN
  SELECT count(*) INTO problem_count
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_roles owner_role ON owner_role.oid = c.relowner
  WHERE n.nspname = 'app'
    AND c.relkind IN ('r', 'p')
    AND (
      NOT c.relrowsecurity
      OR NOT c.relforcerowsecurity
      OR owner_role.rolname <> 'tenant_migrator'
    );
  IF problem_count <> 0 THEN
    RAISE EXCEPTION '% application table(s) lack ENABLE/FORCE RLS or the expected non-bypass owner', problem_count;
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
    AND tablename = 'customer_record';
  IF problem_count <> 1 THEN
    RAISE EXCEPTION 'customer_record must have exactly one reviewed policy; found %', problem_count;
  END IF;

  SELECT count(*) INTO problem_count
  FROM pg_policies
  WHERE schemaname = 'app'
    AND tablename = 'customer_record'
    AND policyname = 'tenant_isolation'
    AND cmd = 'ALL'
    AND permissive = 'PERMISSIVE'
    AND cardinality(roles) = 2
    AND ARRAY['tenant_migrator', 'tenant_runtime']::name[] <@ roles
    AND qual IS NOT NULL
    AND with_check IS NOT NULL
    AND qual ~ 'current_setting'
    AND with_check ~ 'current_setting'
    AND lower(btrim(qual)) NOT IN ('true', '(true)')
    AND lower(btrim(with_check)) NOT IN ('true', '(true)');
  IF problem_count <> 1 THEN
    RAISE EXCEPTION 'tenant policy scope, roles, USING, or WITH CHECK expression is not fail-closed';
  END IF;
END;
$$;

\echo 'PASS: catalog tests reject missing FORCE RLS, bypass roles, extra policies, and incomplete expressions'
