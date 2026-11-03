"use strict";
const assert = require("node:assert/strict");
const test = require("node:test");
const {EventHandler, SecretCache} = require("./lifecycle");

function fixture() {
  let now = 100;
  let version = 1;
  let unavailable = false;
  const calls = [];
  const cache = new SecretCache(async () => {
    if (unavailable) throw new Error("SECRET_UNAVAILABLE");
    return {version: `version-${version}`, value: `<synthetic-secret-${version}>`};
  }, () => now, 1000);
  const handler = new EventHandler({clock: () => now, secrets: cache, execute: async call => calls.push(call)});
  return {handler, calls, cache, advance: ms => { now += ms; }, rotate: () => { version++; },
    failProvider: () => { unavailable = true; }};
}
const context = {verified: true, producer: "owned-queue", tenant: "tenant-a"};
const event = {id: "event-a", tenant: "tenant-a", issuedAt: 100, value: "<synthetic-payload>"};

test("valid event, duplicate and concurrent duplicate produce one side effect", async () => {
  const f = fixture();
  const results = await Promise.all([f.handler.handle(context, event), f.handler.handle(context, event)]);
  assert.deepEqual(results.map(r => r.status), ["completed", "duplicate"]);
  assert.equal(f.calls.length, 1);
});

test("producer, tenant, time and schema failures have no side effect", async () => {
  const f = fixture();
  for (const [ctx, input, reason] of [
    [{...context, verified: false}, event, "PRODUCER_DENIED"],
    [{...context, producer: "other-queue"}, event, "PRODUCER_DENIED"],
    [context, {...event, tenant: "tenant-b"}, "TENANT_DENIED"],
    [context, {...event, issuedAt: 101}, "EVENT_STALE"],
    [context, {...event, issuedAt: -1000}, "EVENT_STALE"],
    [context, {...event, admin: true}, "EVENT_INVALID"],
    [context, {...event, value: "x".repeat(101)}, "EVENT_INVALID"],
  ]) await assert.rejects(f.handler.handle(ctx, input), new RegExp(reason));
  assert.equal(f.calls.length, 0);
});

test("same event ID cannot hide changed payload", async () => {
  const f = fixture();
  await f.handler.handle(context, event);
  await assert.rejects(f.handler.handle(context, {...event, value: "changed"}), /IDEMPOTENCY_CONFLICT/);
  assert.equal(f.calls.length, 1);
});

test("warm process preserves distinct tenant context and tenant-scoped IDs", async () => {
  const f = fixture();
  await f.handler.handle(context, event);
  await f.handler.handle({...context, tenant: "tenant-b"}, {...event, tenant: "tenant-b"});
  assert.deepEqual(f.calls.map(call => call.tenant), ["tenant-a", "tenant-b"]);
});

test("cache has measured deterministic refresh boundary and fails closed on outage", async () => {
  const f = fixture();
  assert.equal((await f.cache.get()).version, "version-1");
  f.rotate();
  f.advance(999);
  assert.equal((await f.cache.get()).version, "version-1");
  f.advance(1);
  assert.equal((await f.cache.get()).version, "version-2");
  f.failProvider();
  f.advance(1000);
  await assert.rejects(f.cache.get(), /SECRET_UNAVAILABLE/);
  assert.equal(f.cache.cached, null);
});

test("failed secret refresh cannot execute an event or leak payload in audit", async () => {
  const f = fixture();
  f.failProvider();
  await assert.rejects(f.handler.handle(context, event), /SECRET_UNAVAILABLE/);
  assert.equal(f.calls.length, 0);
  assert.ok(!JSON.stringify(f.handler.audit).includes(event.value));
  assert.ok(!JSON.stringify(f.handler.audit).includes("synthetic-secret"));
});
