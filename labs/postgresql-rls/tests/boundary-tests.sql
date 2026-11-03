\set ON_ERROR_STOP on
\pset pager off

CREATE OR REPLACE FUNCTION pg_temp.assert_equal(actual bigint, expected bigint, message text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF actual IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'assertion failed: % (actual %, expected %)', message, actual, expected;
  END IF;
END;
$$;

SET ROLE tenant_runtime;

BEGIN;
SELECT set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', true);
DO $$
BEGIN
  BEGIN
    UPDATE app.customer_record
    SET tenant_id = '22222222-2222-2222-2222-222222222222'
    WHERE id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    RAISE EXCEPTION 'tenant-key mutation unexpectedly succeeded';
  EXCEPTION
    WHEN insufficient_privilege THEN
      RAISE NOTICE 'PASS: WITH CHECK rejected mutation of an owned row into another tenant';
  END;
END;
$$;
ROLLBACK;

RESET ROLE;
SET ROLE tenant_migrator;

BEGIN;
SELECT set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', true);
SELECT pg_temp.assert_equal(
  (SELECT count(*) FROM app.customer_record),
  1,
  'FORCE ROW LEVEL SECURITY constrains the table owner'
);
SELECT pg_temp.assert_equal(
  (SELECT count(*) FROM app.customer_record
   WHERE tenant_id = '22222222-2222-2222-2222-222222222222'),
  0,
  'the table owner cannot read another tenant while FORCE RLS is active'
);
ROLLBACK;

RESET ROLE;
\echo 'PASS: tenant-key mutation and table-owner FORCE RLS tests completed'
