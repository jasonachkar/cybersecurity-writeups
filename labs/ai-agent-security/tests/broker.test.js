"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  ApprovalStore,
  BrokerDenied,
  ToolBroker,
  hashActionBinding,
} = require("../broker");

const NOW_MS = Date.parse("2026-07-23T12:00:00Z");

const POLICY = Object.freeze({
  principals: Object.freeze({
    "agent-workload-alpha": Object.freeze({
      tenants: Object.freeze(["tenant-alpha"]),
      tools: Object.freeze({
        "payments.create": Object.freeze({
          maxAmountCents: 100_000,
          approvalRequiredAtCents: 25_000,
          allowedDestinationRefs: Object.freeze([
            "approved-destination",
          ]),
        }),
      }),
    }),
  }),
});

function proposedCall(overrides = {}) {
  return {
    tenantId: "tenant-alpha",
    tool: "payments.create",
    arguments: {
      amountCents: 10_000,
      destinationRef: "approved-destination",
    },
    ...overrides,
  };
}

function approvalRecord(overrides = {}) {
  return {
    id: "approval-example-001",
    decision: "approved",
    principalId: "agent-workload-alpha",
    tenantId: "tenant-alpha",
    tool: "payments.create",
    amountCents: 30_000,
    destinationRef: "approved-destination",
    expiresAtMs: NOW_MS + 60_000,
    ...overrides,
  };
}

function makeHarness({
  enabled = true,
  approvals = [],
  readDelayMs = 0,
  approvalStore,
  executor,
} = {}) {
  const invocations = [];
  const auditEvents = [];
  const store =
    approvalStore ??
    new ApprovalStore(approvals, {readDelayMs});

  const broker = new ToolBroker({
    policy: POLICY,
    approvalStore: store,
    executor:
      executor ??
      (async (authorizedCall) => {
        invocations.push(authorizedCall);
        return {
          status: "simulated",
          invocationNumber: invocations.length,
        };
      }),
    isExecutionEnabled: async () => enabled,
    audit: (event) => auditEvents.push(event),
    clock: () => NOW_MS,
  });

  return {
    auditEvents,
    broker,
    invocations,
    store,
  };
}

async function expectDenied(promiseFactory, expectedCode) {
  await assert.rejects(
    promiseFactory,
    (error) => {
      assert.ok(error instanceof BrokerDenied);
      assert.equal(error.code, expectedCode);
      return true;
    },
  );
}

test("allows an authorized low-impact call without approval", async () => {
  const harness = makeHarness();

  const result = await harness.broker.execute(
    {principalId: "agent-workload-alpha"},
    proposedCall(),
  );

  assert.deepEqual(result, {
    status: "simulated",
    invocationNumber: 1,
  });
  assert.equal(harness.invocations.length, 1);
  assert.deepEqual(harness.invocations[0], {
    principalId: "agent-workload-alpha",
    tenantId: "tenant-alpha",
    tool: "payments.create",
    arguments: {
      amountCents: 10_000,
      destinationRef: "approved-destination",
    },
    approvalId: null,
  });
  assert.equal(harness.auditEvents[0].outcome, "allow");
  assert.equal(harness.auditEvents[1].outcome, "success");
});

test("rejects a high-impact call with missing approval", async () => {
  const harness = makeHarness();
  const call = proposedCall({
    arguments: {
      amountCents: 30_000,
      destinationRef: "approved-destination",
    },
  });

  await expectDenied(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        call,
      ),
    "APPROVAL_REQUIRED",
  );
  assert.equal(harness.invocations.length, 0);
});

test("rejects an expired approval", async () => {
  const approval = approvalRecord({expiresAtMs: NOW_MS});
  const harness = makeHarness({approvals: [approval]});
  const call = proposedCall({
    arguments: {
      amountCents: 30_000,
      destinationRef: "approved-destination",
    },
  });

  await expectDenied(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        call,
        {id: approval.id},
      ),
    "APPROVAL_EXPIRED",
  );
  assert.equal(harness.invocations.length, 0);
});

test("rejects approval bound to a different amount", async () => {
  const approval = approvalRecord({amountCents: 30_001});
  const harness = makeHarness({approvals: [approval]});
  const call = proposedCall({
    arguments: {
      amountCents: 30_000,
      destinationRef: "approved-destination",
    },
  });

  await expectDenied(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        call,
        {id: approval.id},
      ),
    "APPROVAL_SCOPE_MISMATCH",
  );
  assert.equal(harness.invocations.length, 0);
});

test("allows an exactly bound high-impact approval and rejects sequential replay", async () => {
  const approval = approvalRecord();
  const harness = makeHarness({approvals: [approval]});
  const call = proposedCall({
    arguments: {
      amountCents: 30_000,
      destinationRef: "approved-destination",
    },
  });

  await harness.broker.execute(
    {principalId: "agent-workload-alpha"},
    call,
    {id: approval.id},
  );
  assert.equal(harness.invocations.length, 1);
  assert.equal(harness.invocations[0].approvalId, approval.id);

  await expectDenied(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        call,
        {id: approval.id},
      ),
    "APPROVAL_REPLAYED",
  );
  assert.equal(harness.invocations.length, 1);
});

test("consumes approval only once under concurrent replay", async () => {
  const approval = approvalRecord();
  // Delay the read so both requests overlap before either consumption.
  const harness = makeHarness({approvals: [approval], readDelayMs: 40});
  const call = proposedCall({
    arguments: {
      amountCents: 30_000,
      destinationRef: "approved-destination",
    },
  });
  const context = {principalId: "agent-workload-alpha"};
  const evidence = {id: approval.id};

  const results = await Promise.allSettled([
    harness.broker.execute(context, call, evidence),
    harness.broker.execute(context, call, evidence),
  ]);

  assert.equal(harness.invocations.length, 1);
  assert.equal(
    results.filter((result) => result.status === "fulfilled").length,
    1,
  );
  assert.equal(
    results.filter((result) => result.status === "rejected").length,
    1,
  );
  const rejected = results.find((result) => result.status === "rejected");
  assert.ok(rejected.reason instanceof BrokerDenied);
  assert.equal(rejected.reason.code, "APPROVAL_REPLAYED");
});

test("does not free a consumed approval when the executor fails", async () => {
  const approval = approvalRecord();
  const store = new ApprovalStore([approval]);
  let attempts = 0;
  const harness = makeHarness({
    approvalStore: store,
    executor: async () => {
      attempts += 1;
      throw new Error("simulated executor failure");
    },
  });
  const call = proposedCall({
    arguments: {
      amountCents: 30_000,
      destinationRef: "approved-destination",
    },
  });

  await assert.rejects(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        call,
        {id: approval.id},
      ),
    /simulated executor failure/,
  );
  assert.equal(attempts, 1);

  await expectDenied(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        call,
        {id: approval.id},
      ),
    "APPROVAL_REPLAYED",
  );
  assert.equal(attempts, 1);
});

test("fails closed when approval store read throws", async () => {
  const store = {
    async getApprovedAction() {
      throw new Error("store unavailable");
    },
    async consumeIfUnused() {
      return true;
    },
  };
  const harness = makeHarness({approvalStore: store});
  const call = proposedCall({
    arguments: {
      amountCents: 30_000,
      destinationRef: "approved-destination",
    },
  });

  await expectDenied(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        call,
        {id: "approval-example-001"},
      ),
    "APPROVAL_STORE_ERROR",
  );
  assert.equal(harness.invocations.length, 0);
});

test("fails closed when approval store consume throws", async () => {
  const approval = approvalRecord();
  const store = {
    async getApprovedAction() {
      return approval;
    },
    async consumeIfUnused() {
      throw new Error("consume unavailable");
    },
  };
  const harness = makeHarness({approvalStore: store});
  const call = proposedCall({
    arguments: {
      amountCents: 30_000,
      destinationRef: "approved-destination",
    },
  });

  await expectDenied(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        call,
        {id: approval.id},
      ),
    "APPROVAL_STORE_ERROR",
  );
  assert.equal(harness.invocations.length, 0);
});

test("rejects all calls while the independently injected kill switch is active", async () => {
  const harness = makeHarness({enabled: false});

  await expectDenied(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        proposedCall(),
      ),
    "EXECUTION_DISABLED",
  );
  assert.equal(harness.invocations.length, 0);
});

test("rejects unknown arguments instead of passing them to the executor", async () => {
  const harness = makeHarness();
  const call = proposedCall({
    arguments: {
      amountCents: 10_000,
      destinationRef: "approved-destination",
      modelSuppliedAuthority: "allow-everything",
    },
  });

  await expectDenied(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        call,
      ),
    "UNKNOWN_ARGUMENT",
  );
  assert.equal(harness.invocations.length, 0);
});

test("rejects a tenant that the authenticated principal does not own", async () => {
  const harness = makeHarness();

  await expectDenied(
    () =>
      harness.broker.execute(
        {principalId: "agent-workload-alpha"},
        proposedCall({tenantId: "tenant-beta"}),
      ),
    "UNAUTHORIZED_TENANT",
  );
  assert.equal(harness.invocations.length, 0);
});

test("hashActionBinding is SHA-256 hex and changes when any bound field changes", () => {
  const base = {
    principalId: "agent-workload-alpha",
    tenantId: "tenant-alpha",
    tool: "payments.create",
    amountCents: 30_000,
    destinationRef: "approved-destination",
  };
  const digest = hashActionBinding(base);
  assert.match(digest, /^[a-f0-9]{64}$/);

  for (const [key, value] of Object.entries({
    principalId: "agent-workload-beta",
    tenantId: "tenant-beta",
    tool: "payments.refund",
    amountCents: 30_001,
    destinationRef: "other-destination",
  })) {
    const mutated = {...base, [key]: value};
    assert.notEqual(
      hashActionBinding(mutated),
      digest,
      `expected hash to change when ${key} changes`,
    );
  }
});

test("delimiter-containing identifiers do not collide under hashActionBinding", () => {
  // Under a NUL-joined serialization, ("a\0b", "c") and ("a", "b\0c") collide.
  // JSON canonicalization must keep them distinct for every bound string field.
  const left = hashActionBinding({
    principalId: "a\u0000b",
    tenantId: "c",
    tool: "payments.create",
    amountCents: 1,
    destinationRef: "dest",
  });
  const right = hashActionBinding({
    principalId: "a",
    tenantId: "b\u0000c",
    tool: "payments.create",
    amountCents: 1,
    destinationRef: "dest",
  });
  assert.notEqual(left, right);

  const joinLeft = ["a\u0000b", "c", "payments.create", "1", "dest"].join("\u0000");
  const joinRight = ["a", "b\u0000c", "payments.create", "1", "dest"].join("\u0000");
  assert.equal(joinLeft, joinRight);
});
