#!/usr/bin/env node
"use strict";

/**
 * Tested teaching implementation for labs/ai-agent-security.
 *
 * This broker receives authenticated context separately from the model-proposed
 * call. It demonstrates deterministic authorization; it does not validate
 * identity tokens, make network requests, or issue real credentials.
 *
 * Approval consumption uses an in-memory atomic compare-and-set that models a
 * durable conditional write. Production systems must use a durable store such
 * as a PostgreSQL conditional update / unique insert, Redis SET NX, DynamoDB
 * conditional write, or another transactionally enforced compare-and-set.
 * A JavaScript Set is not equivalent to a distributed durable store.
 */

class BrokerDenied extends Error {
  constructor(code, message) {
    super(message);
    this.name = "BrokerDenied";
    this.code = code;
  }
}

function deny(code, message) {
  throw new BrokerDenied(code, message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireRecord(value, code, label) {
  if (!isRecord(value)) deny(code, `${label} must be an object`);
  return value;
}

function requireIdentifier(value, code, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 128) {
    deny(code, `${label} must be a nonempty string of at most 128 characters`);
  }
  return value;
}

function requireSafePositiveInteger(value, code, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    deny(code, `${label} must be a positive safe integer`);
  }
  return value;
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

const {createHash} = require("node:crypto");

/**
 * Canonical action binding for approval consumption.
 * Key order is fixed. The hash is SHA-256 of JSON.stringify of that object —
 * not a delimiter-joined string (which would be ambiguous for attacker-controlled
 * identifier characters).
 */
function canonicalActionBinding(binding) {
  return {
    principalId: binding.principalId,
    tenantId: binding.tenantId,
    tool: binding.tool,
    amountCents: binding.amountCents,
    destinationRef: binding.destinationRef
  };
}

function hashActionBinding(binding) {
  const canonical = JSON.stringify(canonicalActionBinding(binding));
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

/** @deprecated Use hashActionBinding; retained name for ApprovalStore callers. */
function digestAction(binding) {
  return hashActionBinding(binding);
}

function safeAuditMetadata(authenticatedContext, proposedCall) {
  const args = isRecord(proposedCall?.arguments) ? proposedCall.arguments : {};
  return {
    principalId:
      typeof authenticatedContext?.principalId === "string"
        ? authenticatedContext.principalId
        : "<invalid>",
    tenantId:
      typeof proposedCall?.tenantId === "string"
        ? proposedCall.tenantId
        : "<invalid>",
    tool:
      typeof proposedCall?.tool === "string" ? proposedCall.tool : "<invalid>",
    amountCents:
      Number.isSafeInteger(args.amountCents) ? args.amountCents : null,
    destinationRef:
      typeof args.destinationRef === "string"
        ? args.destinationRef
        : "<invalid>",
  };
}

/**
 * In-memory approval store that models durable conditional consumption.
 *
 * getApprovedAction is read-only. consumeIfUnused serializes consumption so
 * only one concurrent caller can observe an unused approval and mark it
 * consumed. Consumed state is not reverted if a later executor fails;
 * production systems should reconcile by idempotency key before retrying.
 */
class ApprovalStore {
  #approvals = new Map();
  #consumed = new Map();
  #mutex = Promise.resolve();
  #readDelayMs;

  constructor(approvals = [], {readDelayMs = 0} = {}) {
    this.#readDelayMs = readDelayMs;
    for (const approval of approvals) {
      if (!isRecord(approval) || typeof approval.id !== "string") {
        throw new TypeError("each approval must be an object with an id");
      }
      this.#approvals.set(approval.id, Object.freeze({...approval}));
    }
  }

  async getApprovedAction(approvalId) {
    if (this.#readDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.#readDelayMs));
    }
    return this.#approvals.get(approvalId) ?? null;
  }

  /**
   * Atomically consume an approval if it is unused and still bound to the
   * supplied action digest. Returns true only for the first valid consumption.
   */
  async consumeIfUnused({approvalId, actionDigest, nowMs}) {
    const run = this.#mutex.then(() => {
      if (typeof approvalId !== "string" || approvalId.length < 1) {
        return false;
      }
      if (typeof actionDigest !== "string" || actionDigest.length < 1) {
        return false;
      }
      if (!Number.isSafeInteger(nowMs)) {
        return false;
      }
      if (this.#consumed.has(approvalId)) {
        return false;
      }

      const approval = this.#approvals.get(approvalId);
      if (!isRecord(approval) || approval.decision !== "approved") {
        return false;
      }
      if (!Number.isSafeInteger(approval.expiresAtMs) || approval.expiresAtMs <= nowMs) {
        return false;
      }

      const expectedDigest = digestAction({
        principalId: approval.principalId,
        tenantId: approval.tenantId,
        tool: approval.tool,
        amountCents: approval.amountCents,
        destinationRef: approval.destinationRef,
      });
      if (expectedDigest !== actionDigest) {
        return false;
      }

      // Durable CAS model: mark consumed before returning success. Executor
      // failure must not free the approval for a second attempt.
      this.#consumed.set(approvalId, {
        actionDigest,
        consumedAtMs: nowMs,
      });
      return true;
    });

    this.#mutex = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

class ToolBroker {
  #approvalStore;
  #audit;
  #clock;
  #executor;
  #isExecutionEnabled;
  #policy;

  constructor({
    policy,
    approvalStore,
    executor,
    isExecutionEnabled = () => true,
    audit = () => {},
    clock = () => Date.now(),
  }) {
    if (!isRecord(policy) || !isRecord(policy.principals)) {
      throw new TypeError("policy.principals must be an object");
    }
    if (
      approvalStore == null ||
      typeof approvalStore.getApprovedAction !== "function" ||
      typeof approvalStore.consumeIfUnused !== "function"
    ) {
      throw new TypeError(
        "approvalStore must implement getApprovedAction and consumeIfUnused",
      );
    }
    if (typeof executor !== "function") {
      throw new TypeError("executor must be a function");
    }
    if (typeof isExecutionEnabled !== "function") {
      throw new TypeError("isExecutionEnabled must be a function");
    }
    if (typeof audit !== "function") {
      throw new TypeError("audit must be a function");
    }
    if (typeof clock !== "function") {
      throw new TypeError("clock must be a function");
    }

    this.#policy = policy;
    this.#approvalStore = approvalStore;
    this.#executor = executor;
    this.#isExecutionEnabled = isExecutionEnabled;
    this.#audit = audit;
    this.#clock = clock;
  }

  async execute(authenticatedContext, proposedCall, approvalEvidence = null) {
    const auditMetadata = safeAuditMetadata(authenticatedContext, proposedCall);

    try {
      const authorizedCall = await this.#authorize(
        authenticatedContext,
        proposedCall,
        approvalEvidence,
      );

      // A production high-impact path should fail closed if this durable audit
      // decision cannot be recorded. This lab's injected audit sink is in-memory.
      this.#audit({
        event: "authorization_decision",
        outcome: "allow",
        reason: "POLICY_ALLOWED",
        ...auditMetadata,
        approvalId: authorizedCall.approvalId,
      });

      try {
        const result = await this.#executor(authorizedCall);
        this.#audit({
          event: "execution_outcome",
          outcome: "success",
          ...auditMetadata,
          approvalId: authorizedCall.approvalId,
        });
        return result;
      } catch (error) {
        this.#audit({
          event: "execution_outcome",
          outcome: "failure",
          reason: "EXECUTOR_FAILED",
          ...auditMetadata,
          approvalId: authorizedCall.approvalId,
        });
        throw error;
      }
    } catch (error) {
      if (error instanceof BrokerDenied) {
        this.#audit({
          event: "authorization_decision",
          outcome: "deny",
          reason: error.code,
          ...auditMetadata,
          approvalId:
            isRecord(approvalEvidence) &&
            typeof approvalEvidence.id === "string"
              ? approvalEvidence.id
              : null,
        });
      }
      throw error;
    }
  }

  async #authorize(authenticatedContext, proposedCall, approvalEvidence) {
    const context = requireRecord(
      authenticatedContext,
      "INVALID_CONTEXT",
      "authenticatedContext",
    );
    const principalId = requireIdentifier(
      context.principalId,
      "INVALID_CONTEXT",
      "authenticatedContext.principalId",
    );

    const call = requireRecord(
      proposedCall,
      "INVALID_CALL",
      "proposedCall",
    );
    const tenantId = requireIdentifier(
      call.tenantId,
      "INVALID_CALL",
      "proposedCall.tenantId",
    );
    const tool = requireIdentifier(
      call.tool,
      "INVALID_CALL",
      "proposedCall.tool",
    );
    const args = requireRecord(
      call.arguments,
      "INVALID_ARGUMENTS",
      "proposedCall.arguments",
    );

    const allowedArgumentNames = new Set([
      "amountCents",
      "destinationRef",
    ]);
    for (const argumentName of Object.keys(args)) {
      if (!allowedArgumentNames.has(argumentName)) {
        deny(
          "UNKNOWN_ARGUMENT",
          `argument ${argumentName} is not in the closed schema`,
        );
      }
    }

    const amountCents = requireSafePositiveInteger(
      args.amountCents,
      "INVALID_AMOUNT",
      "proposedCall.arguments.amountCents",
    );
    const destinationRef = requireIdentifier(
      args.destinationRef,
      "INVALID_DESTINATION",
      "proposedCall.arguments.destinationRef",
    );

    const executionEnabled = await this.#isExecutionEnabled({
      principalId,
      tenantId,
      tool,
    });
    if (executionEnabled !== true) {
      deny("EXECUTION_DISABLED", "the execution kill switch is active");
    }

    if (!hasOwn(this.#policy.principals, principalId)) {
      deny("UNAUTHORIZED_PRINCIPAL", "principal is not registered");
    }
    const principalPolicy = requireRecord(
      this.#policy.principals[principalId],
      "INVALID_POLICY",
      "principal policy",
    );

    if (
      !Array.isArray(principalPolicy.tenants) ||
      !principalPolicy.tenants.includes(tenantId)
    ) {
      deny("UNAUTHORIZED_TENANT", "principal cannot act for this tenant");
    }

    if (!isRecord(principalPolicy.tools) || !hasOwn(principalPolicy.tools, tool)) {
      deny("UNAUTHORIZED_TOOL", "tool is not allowed for this principal");
    }
    const toolPolicy = requireRecord(
      principalPolicy.tools[tool],
      "INVALID_POLICY",
      "tool policy",
    );

    const maxAmountCents = requireSafePositiveInteger(
      toolPolicy.maxAmountCents,
      "INVALID_POLICY",
      "tool policy maxAmountCents",
    );
    const approvalRequiredAtCents = requireSafePositiveInteger(
      toolPolicy.approvalRequiredAtCents,
      "INVALID_POLICY",
      "tool policy approvalRequiredAtCents",
    );
    if (approvalRequiredAtCents > maxAmountCents) {
      deny(
        "INVALID_POLICY",
        "approval threshold cannot exceed the maximum amount",
      );
    }

    if (amountCents > maxAmountCents) {
      deny("AMOUNT_EXCEEDS_POLICY", "amount exceeds the policy maximum");
    }

    if (
      !Array.isArray(toolPolicy.allowedDestinationRefs) ||
      !toolPolicy.allowedDestinationRefs.includes(destinationRef)
    ) {
      deny(
        "UNAUTHORIZED_DESTINATION",
        "destination is not allowed by policy",
      );
    }

    let approvalId = null;
    if (amountCents >= approvalRequiredAtCents) {
      const evidence = requireRecord(
        approvalEvidence,
        "APPROVAL_REQUIRED",
        "approvalEvidence",
      );
      approvalId = requireIdentifier(
        evidence.id,
        "INVALID_APPROVAL",
        "approvalEvidence.id",
      );

      const actionDigest = digestAction({
        principalId,
        tenantId,
        tool,
        amountCents,
        destinationRef,
      });
      const nowMs = this.#clock();

      // Verification (read) and consumption (atomic write) are separated.
      let approval;
      try {
        approval = await this.#approvalStore.getApprovedAction(approvalId);
      } catch {
        deny("APPROVAL_STORE_ERROR", "approval store failed closed");
      }

      if (!isRecord(approval) || approval.decision !== "approved") {
        deny("INVALID_APPROVAL", "approval service did not approve the action");
      }
      if (approval.id !== approvalId) {
        deny("INVALID_APPROVAL", "approval identifier does not match");
      }
      if (
        !Number.isSafeInteger(approval.expiresAtMs) ||
        approval.expiresAtMs <= nowMs
      ) {
        deny("APPROVAL_EXPIRED", "approval has expired");
      }

      const expectedBinding = {
        principalId,
        tenantId,
        tool,
        amountCents,
        destinationRef,
      };
      for (const [field, expectedValue] of Object.entries(expectedBinding)) {
        if (approval[field] !== expectedValue) {
          deny(
            "APPROVAL_SCOPE_MISMATCH",
            `approval is not bound to the requested ${field}`,
          );
        }
      }

      // Consume before invoking the executor. Only one concurrent request may
      // succeed; the loser receives APPROVAL_REPLAYED. Consumed state is not
      // reverted if the executor later fails.
      let consumed;
      try {
        consumed = await this.#approvalStore.consumeIfUnused({
          approvalId,
          actionDigest,
          nowMs,
        });
      } catch {
        deny("APPROVAL_STORE_ERROR", "approval store failed closed");
      }
      if (consumed !== true) {
        deny("APPROVAL_REPLAYED", "approval has already been consumed");
      }
    }

    return Object.freeze({
      principalId,
      tenantId,
      tool,
      arguments: Object.freeze({
        amountCents,
        destinationRef,
      }),
      approvalId,
    });
  }
}

module.exports = {
  ApprovalStore,
  BrokerDenied,
  ToolBroker,
  canonicalActionBinding,
  digestAction,
  hashActionBinding,
};
