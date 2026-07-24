"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  BrokerDenied,
  ToolBroker,
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
} = {}) {
  const invocations = [];
  const auditEvents = [];
  const approvalStore = new Map(
    approvals.map((approval) => [approval.id, approval]),
  );

  const broker = new ToolBroker({
    policy: POLICY,
    approvalVerifier: async ({ id }) => approvalStore.get(id) ?? null,
    executor: async (authorizedCall) => {
      invocations.push(authorizedCall);
      return {
        status: "simulated",
        invocationNumber: invocations.length,
      };
    },
    isExecutionEnabled: async () => enabled,
    audit: (event) => auditEvents.push(event),
    clock: () => NOW_MS,
  });

  return {
    auditEvents,
    broker,
    invocations,
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
    { principalId: "agent-workload-alpha" },
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

test("rejects a tenant that the authenticated principal does not own", async () => {
  const harness = makeHarness();

  await expectDenied(
    () =>
      harness.broker.execute(
        { principalId: "agent-workload-alpha" },
        proposedCall({ tenantId: "tenant-beta" }),
      ),
    "UNAUTHORIZED_TENANT",
  );

  assert.equal(harness.invocations.length, 0);
  assert.equal(harness.auditEvents.at(-1).reason, "UNAUTHORIZED_TENANT");
});

test("rejects a tool outside the principal allowlist", async () => {
  const harness = makeHarness();

  await expectDenied(
    () =>
      harness.broker.execute(
        { principalId: "agent-workload-alpha" },
        proposedCall({ tool: "administration.reset" }),
      ),
    "UNAUTHORIZED_TOOL",
  );

  assert.equal(harness.invocations.length, 0);
});

test("rejects an amount above the policy maximum", async () => {
  const harness = makeHarness();
  const call = proposedCall({
    arguments: {
      amountCents: 100_001,
      destinationRef: "approved-destination",
    },
  });

  await expectDenied(
    () =>
      harness.broker.execute(
        { principalId: "agent-workload-alpha" },
        call,
      ),
    "AMOUNT_EXCEEDS_POLICY",
  );

  assert.equal(harness.invocations.length, 0);
});

test("requires separate approval for a high-impact amount", async () => {
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
        { principalId: "agent-workload-alpha" },
        call,
      ),
    "APPROVAL_REQUIRED",
  );

  assert.equal(harness.invocations.length, 0);
});

test("allows an exactly bound high-impact approval and rejects replay", async () => {
  const approval = approvalRecord();
  const harness = makeHarness({ approvals: [approval] });
  const call = proposedCall({
    arguments: {
      amountCents: 30_000,
      destinationRef: "approved-destination",
    },
  });

  await harness.broker.execute(
    { principalId: "agent-workload-alpha" },
    call,
    { id: approval.id },
  );
  assert.equal(harness.invocations.length, 1);
  assert.equal(harness.invocations[0].approvalId, approval.id);

  await expectDenied(
    () =>
      harness.broker.execute(
        { principalId: "agent-workload-alpha" },
        call,
        { id: approval.id },
      ),
    "APPROVAL_REPLAYED",
  );
  assert.equal(harness.invocations.length, 1);
});

test("rejects approval bound to a different amount", async () => {
  const approval = approvalRecord({ amountCents: 30_001 });
  const harness = makeHarness({ approvals: [approval] });
  const call = proposedCall({
    arguments: {
      amountCents: 30_000,
      destinationRef: "approved-destination",
    },
  });

  await expectDenied(
    () =>
      harness.broker.execute(
        { principalId: "agent-workload-alpha" },
        call,
        { id: approval.id },
      ),
    "APPROVAL_SCOPE_MISMATCH",
  );

  assert.equal(harness.invocations.length, 0);
});

test("rejects all calls while the independently injected kill switch is active", async () => {
  const harness = makeHarness({ enabled: false });

  await expectDenied(
    () =>
      harness.broker.execute(
        { principalId: "agent-workload-alpha" },
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
        { principalId: "agent-workload-alpha" },
        call,
      ),
    "UNKNOWN_ARGUMENT",
  );

  assert.equal(harness.invocations.length, 0);
});
