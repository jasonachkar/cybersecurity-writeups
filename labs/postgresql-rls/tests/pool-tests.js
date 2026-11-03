"use strict";

const assert = require("node:assert/strict");
const { Pool } = require("pg");

const password = process.env.POSTGRES_PASSWORD;
assert.ok(password, "POSTGRES_PASSWORD is required for the disposable pooled-client test");

const tenantA = "11111111-1111-1111-1111-111111111111";
const tenantB = "22222222-2222-2222-2222-222222222222";
const recordA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const recordB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

const connection = {
  host: "127.0.0.1",
  port: Number(process.env.POSTGRES_PORT || "55432"),
  database: "tenant_lab",
  user: "tenant_app",
  password,
  application_name: "postgresql-rls-pool-boundary-test",
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 1000,
};

async function backendPid(client) {
  const result = await client.query("SELECT pg_backend_pid() AS pid");
  return Number(result.rows[0].pid);
}

async function beginTenant(client, tenantId) {
  await client.query("BEGIN");
  await client.query("SET LOCAL ROLE tenant_runtime");
  if (tenantId !== null) {
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
  }
}

async function rollback(client) {
  await client.query("ROLLBACK");
}

async function assertMissingContext(client, label) {
  const context = await client.query(
    "SELECT current_setting('app.tenant_id', true) AS tenant_id",
  );
  assert.ok(
    context.rows[0].tenant_id === null || context.rows[0].tenant_id === "",
    `${label}: previous transaction-local tenant context leaked`,
  );
  const visible = await client.query("SELECT id FROM app.customer_record ORDER BY id");
  assert.deepEqual(visible.rows, [], `${label}: missing context must expose no rows`);
}

async function verifySinglePhysicalSessionReuse() {
  const pool = new Pool({ ...connection, max: 1 });
  try {
    const first = await pool.connect();
    let firstPid;
    try {
      firstPid = await backendPid(first);
      await beginTenant(first, tenantA);
      const visible = await first.query("SELECT id FROM app.customer_record ORDER BY id");
      assert.deepEqual(visible.rows.map((row) => row.id), [recordA]);
      await first.query("COMMIT");
    } finally {
      first.release();
    }

    const reused = await pool.connect();
    try {
      assert.equal(await backendPid(reused), firstPid, "max=1 pool should reuse its physical session");
      await beginTenant(reused, null);
      await assertMissingContext(reused, "reacquired physical session");
      await rollback(reused);
    } finally {
      reused.release();
    }

    const errored = await pool.connect();
    try {
      assert.equal(await backendPid(errored), firstPid);
      await beginTenant(errored, tenantA);
      await assert.rejects(
        errored.query("SELECT 1 / 0"),
        (error) => error && error.code === "22012",
        "division error should abort the tenant transaction",
      );
      await rollback(errored);
    } finally {
      errored.release();
    }

    const afterError = await pool.connect();
    try {
      assert.equal(await backendPid(afterError), firstPid);
      await beginTenant(afterError, null);
      await assertMissingContext(afterError, "session after query error");
      await rollback(afterError);
    } finally {
      afterError.release();
    }

    const cancelled = await pool.connect();
    try {
      assert.equal(await backendPid(cancelled), firstPid);
      await beginTenant(cancelled, tenantB);
      await cancelled.query("SET LOCAL statement_timeout = '50ms'");
      await assert.rejects(
        cancelled.query("SELECT pg_sleep(2)"),
        (error) => error && error.code === "57014",
        "statement timeout should cancel the tenant query",
      );
      await rollback(cancelled);
    } finally {
      cancelled.release();
    }

    const afterCancellation = await pool.connect();
    try {
      assert.equal(await backendPid(afterCancellation), firstPid);
      await beginTenant(afterCancellation, null);
      await assertMissingContext(afterCancellation, "session after cancellation");
      await rollback(afterCancellation);
    } finally {
      afterCancellation.release();
    }
  } finally {
    await pool.end();
  }
}

async function verifyConcurrentTenants() {
  const pool = new Pool({ ...connection, max: 2 });
  let readyCount = 0;
  let releaseReady;
  const bothReady = new Promise((resolve) => {
    releaseReady = resolve;
  });

  async function queryAsTenant(tenantId, expectedRecord) {
    const client = await pool.connect();
    try {
      await beginTenant(client, tenantId);
      const pid = await backendPid(client);
      readyCount += 1;
      if (readyCount === 2) {
        releaseReady();
      }
      await bothReady;
      const visible = await client.query("SELECT id FROM app.customer_record ORDER BY id");
      assert.deepEqual(visible.rows.map((row) => row.id), [expectedRecord]);
      await client.query("COMMIT");
      return pid;
    } catch (error) {
      await rollback(client).catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  try {
    const pids = await Promise.all([
      queryAsTenant(tenantA, recordA),
      queryAsTenant(tenantB, recordB),
    ]);
    assert.notEqual(pids[0], pids[1], "concurrent tenants must use independent sessions");

    const clients = await Promise.all([pool.connect(), pool.connect()]);
    try {
      await Promise.all(
        clients.map(async (client, index) => {
          await beginTenant(client, null);
          await assertMissingContext(client, `concurrent pooled session ${index + 1}`);
          await rollback(client);
        }),
      );
    } finally {
      clients.forEach((client) => client.release());
    }
  } finally {
    await pool.end();
  }
}

async function main() {
  await verifySinglePhysicalSessionReuse();
  await verifyConcurrentTenants();
  console.log(
    "PASS: pg 8.22.0 pool tests covered physical-session reuse, missing context, " +
      "errors, cancellation, and concurrent tenants.",
  );
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
