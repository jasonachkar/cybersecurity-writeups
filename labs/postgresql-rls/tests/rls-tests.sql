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
INSERT INTO app.customer_record (id, tenant_id, display_name)
VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 'Tenant A record');
COMMIT;

BEGIN;
SELECT set_config('app.tenant_id', '22222222-2222-2222-2222-222222222222', true);
INSERT INTO app.customer_record (id, tenant_id, display_name)
VALUES ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '22222222-2222-2222-2222-222222222222', 'Tenant B record');
COMMIT;

BEGIN;
SELECT set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', true);
SELECT pg_temp.assert_equal((SELECT count(*) FROM app.customer_record), 1, 'tenant A sees only its row');
SELECT pg_temp.assert_equal((SELECT count(*) FROM app.customer_record WHERE tenant_id = '22222222-2222-2222-2222-222222222222'), 0, 'cross-tenant select returns no row');
DO $$
DECLARE affected bigint;
BEGIN
  UPDATE app.customer_record SET display_name = 'blocked update'
  WHERE id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
  GET DIAGNOSTICS affected = ROW_COUNT;
  PERFORM pg_temp.assert_equal(affected, 0, 'cross-tenant update affects no row');
END;
$$;
ROLLBACK;

BEGIN;
SELECT set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', true);
DO $$
BEGIN
  BEGIN
    INSERT INTO app.customer_record (id, tenant_id, display_name)
    VALUES ('cccccccc-cccc-cccc-cccc-cccccccccccc', '22222222-2222-2222-2222-222222222222', 'must fail');
    RAISE EXCEPTION 'cross-tenant insert unexpectedly succeeded';
  EXCEPTION
    WHEN insufficient_privilege THEN
      RAISE NOTICE 'PASS: cross-tenant insert rejected by WITH CHECK';
  END;
END;
$$;
ROLLBACK;

BEGIN;
RESET app.tenant_id;
SELECT pg_temp.assert_equal((SELECT count(*) FROM app.customer_record), 0, 'missing tenant context sees no rows');
DO $$
BEGIN
  BEGIN
    INSERT INTO app.customer_record (id, tenant_id, display_name)
    VALUES ('dddddddd-dddd-dddd-dddd-dddddddddddd', '11111111-1111-1111-1111-111111111111', 'must fail');
    RAISE EXCEPTION 'insert without context unexpectedly succeeded';
  EXCEPTION
    WHEN insufficient_privilege THEN
      RAISE NOTICE 'PASS: write without tenant context rejected';
  END;
END;
$$;
ROLLBACK;

BEGIN;
DO $$
BEGIN
  PERFORM set_config('app.tenant_id', 'not-a-uuid', true);
  BEGIN
    PERFORM count(*) FROM app.customer_record;
    RAISE EXCEPTION 'malformed tenant context unexpectedly succeeded';
  EXCEPTION
    WHEN invalid_text_representation THEN
      RAISE NOTICE 'PASS: malformed tenant context failed closed';
  END;
END;
$$;
ROLLBACK;

BEGIN;
SELECT set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', true);
SELECT pg_temp.assert_equal((SELECT count(*) FROM app.customer_record), 1, 'connection reuse transaction A');
COMMIT;
BEGIN;
SELECT pg_temp.assert_equal((SELECT count(*) FROM app.customer_record), 0, 'SET LOCAL context cleared before reused transaction');
ROLLBACK;

RESET ROLE;
\echo 'PASS: runtime RLS negative tests completed'
